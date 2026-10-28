package controllerbackup

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Database files are typed byte records, never SQL programs. The restore side
// must compare this metadata to a freshly migrated empty target before INSERT.
type Column struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Nullable  string  `json:"nullable"`
	Charset   *string `json:"charset"`
	Collation *string `json:"collation"`
	Extra     string  `json:"extra"`
	Key       string  `json:"key"`
	Default   *string `json:"default"`
}
type Table struct {
	Schema    int      `json:"schema"`
	Name      string   `json:"table"`
	Columns   []Column `json:"columns"`
	NextID    *string  `json:"next_id"`
	Collation string   `json:"collation"`
}

// The target database name is deliberately NOT inherited from a backup.
// Encoding and comparison defaults are part of the data contract, however.
type DatabaseSchema struct {
	Schema    int    `json:"schema"`
	Charset   string `json:"charset"`
	Collation string `json:"collation"`
}

var sqlName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func tableNames() []string {
	var names []string
	for name := range requiredFiles() {
		if strings.HasPrefix(name, "database/") && strings.HasSuffix(name, ".jsonl") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(name, "database/"), ".jsonl"))
		}
	}
	sort.Strings(names)
	return names
}

// SnapshotDatabase is a single read-only REPEATABLE READ transaction. The
// caller supplies private bounded writers, keeps the source fenced, and has
// already checked the embedded migration checksums. No source rows are written.
func SnapshotDatabase(ctx context.Context, db *sql.DB, write func(string, func(io.Writer) error) error) (int64, error) {
	return snapshotDatabase(ctx, db, nil, write)
}

func snapshotDatabase(ctx context.Context, db *sql.DB, ownership *databaseOwnership, write func(string, func(io.Writer) error) error) (int64, error) {
	return snapshotDatabaseChecked(ctx, db, ownership, write, nil)
}

func snapshotDatabaseChecked(ctx context.Context, db *sql.DB, ownership *databaseOwnership, write func(string, func(io.Writer) error) error, check func(sqlReader) error) (int64, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, ErrInvalid
	}
	defer conn.Close()
	defer discardConnection(conn)
	// AUTO_INCREMENT is restore state, not a cached capacity statistic.
	if _, err = conn.ExecContext(ctx, "SET SESSION information_schema_stats_expiry=0"); err != nil {
		return 0, ErrInvalid
	}
	var locked int
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK('aster_controller_schema_v1',5)").Scan(&locked) != nil || locked != 1 {
		return 0, ErrInvalid
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5_000_000_000)
		defer cancel()
		_, _ = conn.ExecContext(release, "DO RELEASE_LOCK('aster_controller_schema_v1')")
	}()
	if check != nil {
		for _, q := range []string{"SET SESSION sql_quote_show_create=1", "SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO'"} {
			if _, err = conn.ExecContext(ctx, q); err != nil {
				return 0, ErrInvalid
			}
		}
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return 0, ErrInvalid
	}
	defer tx.Rollback()
	count, err := snapshotTablesChecked(ctx, tx, ownership, write, check)
	if err != nil || tx.Commit() != nil {
		return 0, ErrInvalid
	}
	return count, nil
}

// The caller owns one transaction and its session/metadata settings. Sharing
// this exact inventory/ownership path keeps mutation verification from omitting
// tables or applying weaker checks than the read-only backup boundary.
func snapshotTablesChecked(ctx context.Context, tx sqlReader, ownership *databaseOwnership, write func(string, func(io.Writer) error) error, check func(sqlReader) error) (int64, error) {
	names := tableNames()
	inventory := append([]string(nil), names...)
	if ownership != nil {
		inventory = append(inventory, installerOwnershipTable)
		sort.Strings(inventory)
	}
	rows, err := tx.QueryContext(ctx, "SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME")
	if err != nil {
		return 0, ErrInvalid
	}
	index := 0
	for rows.Next() {
		var name, engine, kind string
		if rows.Scan(&name, &engine, &kind) != nil || index >= len(inventory) || name != inventory[index] || engine != "InnoDB" || kind != "BASE TABLE" {
			rows.Close()
			return 0, ErrInvalid
		}
		index++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || index != len(inventory) {
		return 0, ErrInvalid
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE()",
	} {
		var n int
		if tx.QueryRowContext(ctx, query).Scan(&n) != nil || n != 0 {
			return 0, ErrInvalid
		}
	}
	// Obtain metadata locks on every approved table before taking column
	// definitions. These transaction locks remain held through the final read.
	for _, name := range inventory {
		r, e := tx.QueryContext(ctx, "SELECT * FROM `"+name+"` LIMIT 0")
		if e != nil {
			return 0, ErrInvalid
		}
		r.Close()
	}
	if check != nil && check(tx) != nil {
		return 0, ErrInvalid
	}
	schema := DatabaseSchema{Schema: 1}
	if tx.QueryRowContext(ctx, "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=DATABASE()").Scan(&schema.Charset, &schema.Collation) != nil || !sqlName.MatchString(schema.Charset) || !sqlName.MatchString(schema.Collation) {
		return 0, ErrInvalid
	}
	if ownership != nil && verifyDatabaseOwnership(ctx, tx, ownership, schema) != nil {
		return 0, ErrInvalid
	}
	if write("database/schema.json", func(w io.Writer) error { return json.NewEncoder(w).Encode(schema) }) != nil {
		return 0, ErrInvalid
	}
	var count int64
	for _, name := range names {
		table, e := describeTable(ctx, tx, name)
		if e != nil {
			return 0, ErrInvalid
		}
		e = write("database/"+name+".jsonl", func(w io.Writer) error {
			n, e := streamTable(ctx, tx, table, w)
			count += n
			return e
		})
		if e != nil {
			return 0, ErrInvalid
		}
	}
	return count, nil
}

type sqlReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Restore/snapshot session settings and named locks must not leak to a later
// borrower of the caller's connection pool. The driver closes this connection;
// it is not returned as an idle application connection.
func discardConnection(conn *sql.Conn) { _ = conn.Raw(func(any) error { return driver.ErrBadConn }) }

func describeTable(ctx context.Context, q sqlReader, name string) (Table, error) {
	table := Table{Schema: 1, Name: name}
	r, e := q.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,CHARACTER_SET_NAME,COLLATION_NAME,EXTRA,COLUMN_KEY,COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", name)
	if e != nil {
		return Table{}, ErrInvalid
	}
	for r.Next() {
		var c Column
		if r.Scan(&c.Name, &c.Type, &c.Nullable, &c.Charset, &c.Collation, &c.Extra, &c.Key, &c.Default) != nil || !sqlName.MatchString(c.Name) || len(table.Columns) >= 128 || (c.Extra != "" && c.Extra != "auto_increment") {
			r.Close()
			return Table{}, ErrInvalid
		}
		table.Columns = append(table.Columns, c)
	}
	e = r.Err()
	r.Close()
	if e != nil || len(table.Columns) == 0 {
		return Table{}, ErrInvalid
	}
	if q.QueryRowContext(ctx, "SELECT CAST(AUTO_INCREMENT AS CHAR),TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", name).Scan(&table.NextID, &table.Collation) != nil || !sqlName.MatchString(table.Collation) {
		return Table{}, ErrInvalid
	}
	return table, nil
}

func streamTable(ctx context.Context, q sqlReader, table Table, w io.Writer) (int64, error) {
	var columns, primary []string
	for _, c := range table.Columns {
		columns = append(columns, "CAST(`"+c.Name+"` AS BINARY)")
		if c.Key == "PRI" {
			primary = append(primary, "`"+c.Name+"`")
		}
	}
	if len(primary) == 0 {
		return 0, ErrInvalid
	}
	enc := json.NewEncoder(w)
	if enc.Encode(table) != nil {
		return 0, ErrInvalid
	}
	rows, e := q.QueryContext(ctx, "SELECT "+strings.Join(columns, ",")+" FROM `"+table.Name+"` ORDER BY "+strings.Join(primary, ","))
	if e != nil {
		return 0, ErrInvalid
	}
	defer rows.Close()
	values := make([][]byte, len(table.Columns))
	destinations := make([]any, len(values))
	for i := range values {
		destinations[i] = &values[i]
	}
	var count int64
	for rows.Next() {
		if rows.Scan(destinations...) != nil {
			return 0, ErrInvalid
		}
		var size int64
		for _, value := range values {
			size += int64(len(value))
		}
		if size > 48<<20 || enc.Encode(values) != nil {
			return 0, ErrInvalid
		}
		count++
	}
	return count, rows.Err()
}
