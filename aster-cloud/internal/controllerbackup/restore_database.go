package controllerbackup

import (
	"aster/cloud/internal/control"
	"aster/cloud/migrations"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type DatabaseRestoreReport struct {
	Tables                      int   `json:"tables"`
	Rows                        int64 `json:"rows"`
	ExactRowsVerified           bool  `json:"exact_rows_verified"`
	DeclaredConstraintsVerified bool  `json:"declared_constraints_verified"`
	ProvisioningMarkerPreserved bool  `json:"provisioning_marker_preserved"`
	TargetActivationApproved    bool  `json:"target_activation_approved"`
	MigrationReady              bool  `json:"migration_ready"`
}

func (a *Archive) readSmall(name string, maximum int64) ([]byte, error) {
	if a == nil || !a.valid {
		return nil, ErrInvalid
	}
	f, e := os.Open(a.files[name])
	if e != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(raw)) > maximum {
		return nil, ErrInvalid
	}
	return raw, nil
}

func canonicalRecord(raw []byte, value any) bool {
	if !strictRecord(raw, value) {
		return false
	}
	encoded, e := json.Marshal(value)
	return e == nil && bytes.Equal(encoded, raw)
}

func validTable(t Table, name string) bool {
	if t.Schema != 1 || t.Name != name || len(t.Columns) < 1 || len(t.Columns) > 128 || !sqlName.MatchString(t.Collation) {
		return false
	}
	seen := map[string]bool{}
	primary, automatic := 0, 0
	for _, c := range t.Columns {
		if !sqlName.MatchString(c.Name) || seen[c.Name] || len(c.Type) < 1 || len(c.Type) > 256 || (c.Nullable != "YES" && c.Nullable != "NO") || (c.Extra != "" && c.Extra != "auto_increment") {
			return false
		}
		if (c.Charset != nil && !sqlName.MatchString(*c.Charset)) || (c.Collation != nil && !sqlName.MatchString(*c.Collation)) {
			return false
		}
		seen[c.Name] = true
		if c.Key == "PRI" {
			primary++
		}
		if c.Extra == "auto_increment" {
			automatic++
		}
	}
	if primary == 0 || automatic > 1 || (automatic == 1) != (t.NextID != nil) {
		return false
	}
	if t.NextID != nil {
		n, e := strconv.ParseUint(*t.NextID, 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != *t.NextID {
			return false
		}
	}
	return true
}

// Rows use canonical JSONL: no duplicate/case-alias headers, optional final
// line, CRLF normalization or lossy JSON numbers. Values remain nullable bytes.
func (a *Archive) tableRecords(ctx context.Context, name string, header func(Table) error, row func([][]byte) error) (int64, error) {
	if a == nil || !a.valid {
		return 0, ErrInvalid
	}
	f, e := os.Open(a.files["database/"+name+".jsonl"])
	if e != nil {
		return 0, ErrInvalid
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 65<<20)
	s.Split(func(raw []byte, eof bool) (int, []byte, error) {
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			return i + 1, raw[:i], nil
		}
		if eof && len(raw) != 0 {
			return 0, nil, ErrInvalid
		}
		return 0, nil, nil
	})
	var t Table
	if !s.Scan() || len(s.Bytes()) > 256<<10 || !canonicalRecord(s.Bytes(), &t) || !validTable(t, name) {
		return 0, ErrInvalid
	}
	if header != nil && header(t) != nil {
		return 0, ErrInvalid
	}
	var count int64
	for s.Scan() {
		if ctx.Err() != nil {
			return 0, ErrInvalid
		}
		var values [][]byte
		if !canonicalRecord(s.Bytes(), &values) || len(values) != len(t.Columns) {
			return 0, ErrInvalid
		}
		var size int64
		for i, value := range values {
			size += int64(len(value))
			if value == nil && t.Columns[i].Nullable != "YES" {
				return 0, ErrInvalid
			}
		}
		if size > 48<<20 || (row != nil && row(values) != nil) {
			return 0, ErrInvalid
		}
		count++
	}
	if s.Err() != nil {
		return 0, ErrInvalid
	}
	return count, nil
}

// RestoreEmptyDatabase restores data only. The protected target coordinator
// must keep the host sealed, validate installation/configuration, and perform
// the later node-authority transfer before any service activation. This routine
// never writes config, starts a process, contacts a node or edits source data.
// A rejected/partial new schema is retained; never silently deleted/reused.
func (a *Archive) RestoreEmptyDatabase(ctx context.Context, target *sql.DB) (DatabaseRestoreReport, error) {
	return a.restoreDatabase(ctx, target, nil, nil)
}

// RestoreMarkedEmptyDatabase is the data-stage variant for the native
// installer's retained marker. Receipt/DSN bytes must come from the protected
// TARGET provisioning journal, never from the backup's source receipt. This
// verifies the live marker and account binding; it does NOT establish fresh
// database creation, grants, metadata visibility or absence of other writers.
// The root coordinator must prove those properties and keep the target sealed.
// Ordinary RestoreEmptyDatabase retains its strict zero-object requirement.
func (a *Archive) RestoreMarkedEmptyDatabase(ctx context.Context, target *sql.DB, receipt []byte, runtimeDSN string) (DatabaseRestoreReport, error) {
	if len(receipt) > 65536 || len(runtimeDSN) > 4096 {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	runtimeDSN = strings.TrimSpace(runtimeDSN)
	owner, err := decodeDatabaseOwnership(receipt, runtimeDSN)
	if err != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	parsed, err := control.OpenDSN(runtimeDSN) // lazy parser, never connected
	if err != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	parsed.DB.Close()
	return a.restoreDatabase(ctx, target, owner, nil)
}

// DatabasePlan is an authenticated, completely parsed data inventory. It is
// not permission to create a database or proof of live schema compatibility.
// Names/encoding remain data; no SQL program is accepted from the archive.
type DatabasePlan struct {
	Schema    int                 `json:"schema"`
	Charset   string              `json:"charset"`
	Collation string              `json:"collation"`
	Tables    []DatabaseTablePlan `json:"tables"`
	Rows      int64               `json:"rows"`
}
type DatabaseTablePlan struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

func (a *Archive) PlanDatabase(ctx context.Context) (DatabasePlan, error) {
	plan, _, _, err := a.parseDatabase(ctx)
	return plan, err
}

func (a *Archive) parseDatabase(ctx context.Context) (DatabasePlan, map[string]Table, map[string]int64, error) {
	if a == nil || !a.valid || ctx == nil || ctx.Err() != nil {
		return DatabasePlan{}, nil, nil, ErrInvalid
	}
	names := tableNames()
	definitions := map[string]Table{}
	counts := map[string]int64{}
	var schema DatabaseSchema
	raw, e := a.readSmall("database/schema.json", 4096)
	if e != nil || !bytes.HasSuffix(raw, []byte("\n")) || !canonicalRecord(bytes.TrimSuffix(raw, []byte("\n")), &schema) || schema.Schema != 1 || !sqlName.MatchString(schema.Charset) || !sqlName.MatchString(schema.Collation) {
		return DatabasePlan{}, nil, nil, ErrInvalid
	}
	// Authentication and complete bounded record-format validation precede all target
	// schema/data writes. Only current embedded migrations can create structure.
	for _, name := range names {
		count, e := a.tableRecords(ctx, name, func(t Table) error { definitions[name] = t; return nil }, nil)
		if e != nil {
			return DatabasePlan{}, nil, nil, ErrInvalid
		}
		counts[name] = count
	}
	if !a.schemaRowsMatch(ctx) {
		return DatabasePlan{}, nil, nil, ErrInvalid
	}
	plan := DatabasePlan{Schema: 1, Charset: schema.Charset, Collation: schema.Collation}
	for _, name := range names {
		plan.Tables = append(plan.Tables, DatabaseTablePlan{name, counts[name]})
		plan.Rows += counts[name]
	}
	return plan, definitions, counts, nil
}

func (a *Archive) restoreDatabase(ctx context.Context, target *sql.DB, owner *databaseOwnership, persist func([]byte) error) (DatabaseRestoreReport, error) {
	if a == nil || !a.valid || target == nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	names := tableNames()
	plan, definitions, counts, e := a.parseDatabase(ctx)
	if e != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	schema := DatabaseSchema{1, plan.Charset, plan.Collation}
	conn, e := target.Conn(ctx)
	if e != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	defer conn.Close()
	defer discardConnection(conn)
	var database string
	if conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database) != nil || database != "aster_cloud_restore_"+a.manifest.OperationID {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	var locked int
	lock := "aster_restore_" + a.manifest.OperationID
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,0)", lock).Scan(&locked) != nil || locked != 1 {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(c, "DO RELEASE_LOCK(?)", lock)
	}()
	for index, q := range []string{
		"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()",
	} {
		var n int
		want := 0
		if index == 0 && owner != nil {
			want = 1 // only the exact, independently checked marker below
		}
		if conn.QueryRowContext(ctx, q).Scan(&n) != nil || n != want {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	var charset, collation string
	if conn.QueryRowContext(ctx, "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=DATABASE()").Scan(&charset, &collation) != nil || charset != schema.Charset || collation != schema.Collation {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	if owner != nil {
		var account, engine, kind string
		if conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil || account != owner.MigrationUser+"@localhost" ||
			conn.QueryRowContext(ctx, "SELECT ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='aster_installer_ownership'").Scan(&engine, &kind) != nil || engine != "InnoDB" || kind != "BASE TABLE" ||
			verifyDatabaseOwnership(ctx, conn, owner, schema) != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	for _, q := range []string{
		"SET SESSION information_schema_stats_expiry=0",
		"SET SESSION sql_quote_show_create=1",
		"SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO'",
		"SET SESSION foreign_key_checks=1",
	} {
		if _, e = conn.ExecContext(ctx, q); e != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	// This can leave an owned, unactivated partial schema on failure. It cannot
	// touch an existing database: all objects were required absent above.
	store := control.SQLStore{DB: target}
	if store.Migrate(ctx) != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	for _, name := range names {
		have, e := describeTable(ctx, conn, name)
		want := definitions[name]
		if e != nil || !reflect.DeepEqual(have.Columns, want.Columns) || have.Collation != want.Collation || (have.NextID == nil) != (want.NextID == nil) {
			return DatabaseRestoreReport{}, ErrInvalid
		}
		if want.NextID != nil {
			// Parsed canonical unsigned decimal; table names are embedded, never
			// SQL or identifiers taken from untrusted backup content.
			if _, e = conn.ExecContext(ctx, "ALTER TABLE `"+name+"` AUTO_INCREMENT="+*want.NextID); e != nil {
				return DatabaseRestoreReport{}, ErrInvalid
			}
		}
	}
	order, e := restoreOrder(ctx, conn, names, database)
	if e != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	tx, e := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	defer tx.Rollback()
	// SERIALIZABLE locks the retained marker through the entire data commit.
	// If it drifted during DDL, retain the unactivated schema and refuse rows.
	if owner != nil && verifyDatabaseOwnership(ctx, tx, owner, schema) != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	// Only the known migration seeds may be replaced. No broad deletion of
	// foreign rows, INSERT IGNORE, REPLACE, disabled FKs or ignored constraints.
	for _, name := range names {
		var count int64
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+name+"`").Scan(&count) != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
		want := int64(0)
		if name == "controller_schema" {
			want = int64(len(migrations.All()))
		}
		if name == "controller_lock" || name == "controller_identity_lock" {
			want = 1
			var id int
			if tx.QueryRowContext(ctx, "SELECT id FROM `"+name+"`").Scan(&id) != nil || id != 1 {
				return DatabaseRestoreReport{}, ErrInvalid
			}
		}
		if count != want {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	if persist != nil {
		proof, err := a.prepareStructure(ctx, tx, owner)
		if err != nil || persist(proof) != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	for _, name := range []string{"controller_schema", "controller_lock", "controller_identity_lock"} {
		if _, e = tx.ExecContext(ctx, "DELETE FROM `"+name+"`"); e != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	var total int64
	for _, name := range order {
		definition := definitions[name]
		columns := make([]string, len(definition.Columns))
		marks := make([]string, len(columns))
		for i, c := range definition.Columns {
			columns[i] = "`" + c.Name + "`"
			marks[i] = "?"
		}
		stmt, e := tx.PrepareContext(ctx, "INSERT INTO `"+name+"` ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(marks, ",")+")")
		if e != nil {
			return DatabaseRestoreReport{}, ErrInvalid
		}
		count, e := a.tableRecords(ctx, name, func(t Table) error {
			if !reflect.DeepEqual(t, definition) {
				return ErrInvalid
			}
			return nil
		}, func(values [][]byte) error {
			args := make([]any, len(values))
			for i, value := range values {
				if value != nil {
					args[i] = value
				}
			}
			_, e := stmt.ExecContext(ctx, args...)
			return e
		})
		stmt.Close()
		if e != nil || count != counts[name] {
			return DatabaseRestoreReport{}, ErrInvalid
		}
		total += count
	}
	expected := map[string]string{}
	for _, entry := range a.manifest.Files {
		expected[entry.Name] = entry.SHA256
	}
	for _, name := range names {
		t, e := describeTable(ctx, tx, name)
		if e != nil || !reflect.DeepEqual(t, definitions[name]) {
			return DatabaseRestoreReport{}, ErrInvalid
		}
		h := sha256.New()
		count, e := streamTable(ctx, tx, t, h)
		if e != nil || count != counts[name] || hex.EncodeToString(h.Sum(nil)) != expected["database/"+name+".jsonl"] {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	if owner != nil && verifyDatabaseOwnership(ctx, tx, owner, schema) != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	if tx.Commit() != nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	return DatabaseRestoreReport{Tables: len(names), Rows: total, ExactRowsVerified: true, DeclaredConstraintsVerified: true, ProvisioningMarkerPreserved: owner != nil}, nil
}

func (a *Archive) schemaRowsMatch(ctx context.Context) bool {
	var columns []Column
	index := 0
	all := migrations.All()
	count, e := a.tableRecords(ctx, "controller_schema", func(t Table) error {
		columns = t.Columns
		if len(columns) != 3 || columns[0].Name != "version" || columns[1].Name != "sha256" || columns[2].Name != "applied_at" {
			return ErrInvalid
		}
		return nil
	}, func(values [][]byte) error {
		if index >= len(all) || string(values[0]) != strconv.Itoa(all[index].Version) || string(values[1]) != digestBytes([]byte(all[index].SQL)) {
			return ErrInvalid
		}
		index++
		return nil
	})
	return e == nil && count == int64(len(all)) && index == len(all)
}

func restoreOrder(ctx context.Context, q sqlReader, names []string, database string) ([]string, error) {
	parents := map[string]map[string]bool{}
	for _, name := range names {
		parents[name] = map[string]bool{}
	}
	r, e := q.QueryContext(ctx, "SELECT TABLE_NAME,REFERENCED_TABLE_NAME,REFERENCED_TABLE_SCHEMA FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL")
	if e != nil {
		return nil, ErrInvalid
	}
	for r.Next() {
		var child, parent, schema string
		if r.Scan(&child, &parent, &schema) != nil || parents[child] == nil || parents[parent] == nil || schema != database {
			r.Close()
			return nil, ErrInvalid
		}
		parents[child][parent] = true
	}
	e = r.Err()
	r.Close()
	if e != nil {
		return nil, ErrInvalid
	}
	var order []string
	done := map[string]bool{}
	for len(order) < len(names) {
		before := len(order)
		for _, name := range names {
			if done[name] {
				continue
			}
			ready := true
			for parent := range parents[name] {
				if !done[parent] {
					ready = false
				}
			}
			if ready {
				order = append(order, name)
				done[name] = true
			}
		}
		if before == len(order) {
			return nil, ErrInvalid
		}
	}
	return order, nil
}
