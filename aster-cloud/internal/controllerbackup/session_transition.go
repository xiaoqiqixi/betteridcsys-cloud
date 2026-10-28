package controllerbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const sessionTable = "controller_console_sessions"
const identityAuditTable = "controller_identity_audit"

// SessionTransitionBinding is supplied by the protected target coordinator
// after exact material verification. Time is chosen once, before intent is
// persisted. This library does not authorize host activation or prove sealing.
type SessionTransitionBinding struct {
	TargetPlanSHA256       string
	MaterialManifestSHA256 string
	CreatedAt              time.Time
}

type SessionRevocationReport struct {
	Schema                   int    `json:"schema"`
	OperationID              string `json:"operation_id"`
	RevokedSessions          int64  `json:"revoked_sessions"`
	SessionsRevoked          bool   `json:"sessions_revoked"`
	AuditAppended            bool   `json:"audit_appended"`
	ExactDatabaseVerified    bool   `json:"exact_database_verified"`
	ReadOnlyVerification     bool   `json:"read_only_verification"`
	TargetActivationApproved bool   `json:"target_activation_approved"`
	MigrationReady           bool   `json:"migration_ready"`
}

type sessionIntent struct {
	Schema                 int    `json:"schema"`
	OperationID            string `json:"operation_id"`
	ControllerID           string `json:"controller_id"`
	TargetPlanSHA256       string `json:"target_plan_sha256"`
	MaterialManifestSHA256 string `json:"material_manifest_sha256"`
	SourceManifestSHA256   string `json:"source_manifest_sha256"`
	OwnershipSHA256        string `json:"ownership_sha256"`
	StructureSHA256        string `json:"structure_sha256"`
	SourceSessions         int64  `json:"source_sessions"`
	AuditID                string `json:"audit_id"`
	CreatedAt              string `json:"created_at"`
	AuditBeforeDDL         string `json:"audit_before_ddl"`
}

type databaseView struct {
	files     map[string]string
	structure []preparedTable
	rows      int64
	auditDDL  string
}

func sameDatabaseView(a, b databaseView) bool {
	return a.rows == b.rows && reflect.DeepEqual(a.files, b.files) && reflect.DeepEqual(a.structure, b.structure)
}

func viewWriter(view *databaseView) func(string, func(io.Writer) error) error {
	return func(name string, emit func(io.Writer) error) error {
		h := sha256.New()
		if emit(h) != nil {
			return ErrInvalid
		}
		view.files[name] = hex.EncodeToString(h.Sum(nil))
		return nil
	}
}

func viewStructure(ctx context.Context, q sqlReader, owner *databaseOwnership, view *databaseView) error {
	var account, name string
	if q.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil || account != owner.MigrationUser+"@localhost" {
		return ErrInvalid
	}
	var e error
	view.structure, e = structure(ctx, q)
	if e != nil || q.QueryRowContext(ctx, "SHOW CREATE TABLE controller_identity_audit").Scan(&name, &view.auditDDL) != nil || name != identityAuditTable || len(view.auditDDL) > 32768 {
		return ErrInvalid
	}
	return nil
}

func captureSessionView(ctx context.Context, db *sql.DB, tx sqlReader, owner *databaseOwnership) (databaseView, error) {
	view := databaseView{files: map[string]string{}}
	check := func(q sqlReader) error { return viewStructure(ctx, q, owner, &view) }
	var e error
	if tx != nil {
		view.rows, e = snapshotTablesChecked(ctx, tx, owner, viewWriter(&view), check)
	} else if db != nil {
		view.rows, e = snapshotDatabaseChecked(ctx, db, owner, viewWriter(&view), check)
	} else {
		e = ErrInvalid
	}
	return view, e
}

func (a *Archive) originalView(plan DatabasePlan, p databasePreparation) databaseView {
	v := databaseView{files: map[string]string{}, structure: p.Tables, rows: plan.Rows}
	for _, f := range a.manifest.Files {
		if strings.HasPrefix(f.Name, "database/") {
			v.files[f.Name] = f.SHA256
		}
	}
	return v
}

// Only the independently verified, embedded audit table's AUTO_INCREMENT
// option may change. No broad DDL normalization, ignored indexes/FKs, or SQL
// execution from the intent. MySQL omits AUTO_INCREMENT when its value is 1.
func advancedAuditDDL(before, oldID, newID string) (string, error) {
	count := strings.Count(before, " AUTO_INCREMENT=")
	old := " AUTO_INCREMENT=" + oldID + " "
	if count == 1 && strings.Count(before, old) == 1 {
		return strings.Replace(before, old, " AUTO_INCREMENT="+newID+" ", 1), nil
	}
	if count == 0 && oldID == "1" && strings.Count(before, ") ENGINE=InnoDB ") == 1 {
		return strings.Replace(before, ") ENGINE=InnoDB ", ") ENGINE=InnoDB AUTO_INCREMENT="+newID+" ", 1), nil
	}
	return "", ErrInvalid
}

func (a *Archive) sessionExpectation(ctx context.Context, plan DatabasePlan, p databasePreparation, proof []byte, b SessionTransitionBinding, ddl string) (sessionIntent, databaseView, databaseView, error) {
	fail := func() (sessionIntent, databaseView, databaseView, error) {
		return sessionIntent{}, databaseView{}, databaseView{}, ErrInvalid
	}
	_, offset := b.CreatedAt.Zone()
	if !shaPattern.MatchString(b.TargetPlanSHA256) || !shaPattern.MatchString(b.MaterialManifestSHA256) || b.CreatedAt.Year() < 2000 || b.CreatedAt.Year() > 9999 || offset != 0 || b.CreatedAt.Nanosecond()%1000 != 0 || len(ddl) == 0 || len(ddl) > 32768 {
		return fail()
	}
	matched := false
	for _, t := range p.Tables {
		if t.Name == identityAuditTable && t.SHA256 == digestBytes([]byte(ddl)) {
			matched = true
		}
	}
	if !matched {
		return fail()
	}
	var sessions, audit Table
	n, e := a.tableRecords(ctx, sessionTable, func(t Table) error { sessions = t; return nil }, nil)
	if e != nil || sessions.NextID != nil {
		return fail()
	}
	var lastID int64 = math.MinInt64
	_, e = a.tableRecords(ctx, identityAuditTable, func(t Table) error {
		audit = t
		if len(t.Columns) != 5 || t.NextID == nil {
			return ErrInvalid
		}
		for i, name := range []string{"id", "actor", "action", "target", "created_at"} {
			if t.Columns[i].Name != name {
				return ErrInvalid
			}
		}
		if t.Columns[0].Type != "bigint" || t.Columns[0].Extra != "auto_increment" || t.Columns[0].Key != "PRI" {
			return ErrInvalid
		}
		return nil
	}, func(row [][]byte) error {
		id, e := strconv.ParseInt(string(row[0]), 10, 64)
		if e != nil || strconv.FormatInt(id, 10) != string(row[0]) || id <= lastID {
			return ErrInvalid
		}
		lastID = id
		return nil
	})
	if e != nil {
		return fail()
	}
	next, e := strconv.ParseInt(*audit.NextID, 10, 64)
	if e != nil || next < 1 || next >= math.MaxInt64 || lastID >= next {
		return fail()
	}
	newID := strconv.FormatInt(next+1, 10)
	postDDL, e := advancedAuditDDL(ddl, *audit.NextID, newID)
	if e != nil {
		return fail()
	}
	intent := sessionIntent{Schema: 1, OperationID: a.manifest.OperationID, ControllerID: a.manifest.ControllerID,
		TargetPlanSHA256: b.TargetPlanSHA256, MaterialManifestSHA256: b.MaterialManifestSHA256,
		SourceManifestSHA256: p.ManifestSHA256, OwnershipSHA256: p.OwnershipSHA256,
		StructureSHA256: digestBytes(proof), SourceSessions: n, AuditID: *audit.NextID,
		CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339Nano), AuditBeforeDDL: ddl}
	// The recoverable intermediate state has every original row, but the one
	// predetermined audit counter was consumed by a rolled-back transaction.
	// No table is excluded and no arbitrary counter drift is tolerated.
	pending := a.originalView(plan, p)
	pending.structure = append([]preparedTable(nil), p.Tables...)
	for i := range pending.structure {
		if pending.structure[i].Name == identityAuditTable {
			pending.structure[i].SHA256 = digestBytes([]byte(postDDL))
		}
	}
	post := a.originalView(plan, p)
	post.structure = append([]preparedTable(nil), pending.structure...)
	post.rows = plan.Rows - n + 1
	audit.NextID = &newID
	h := sha256.New()
	enc := json.NewEncoder(h)
	if enc.Encode(audit) != nil {
		return fail()
	}
	_, e = a.tableRecords(ctx, identityAuditTable, nil, func(row [][]byte) error { return enc.Encode(row) })
	if e != nil {
		return fail()
	}
	pending.files["database/"+identityAuditTable+".jsonl"] = hex.EncodeToString(h.Sum(nil))
	if enc.Encode(intent.auditRow()) != nil {
		return fail()
	}
	post.files["database/"+identityAuditTable+".jsonl"] = hex.EncodeToString(h.Sum(nil))
	h = sha256.New()
	if json.NewEncoder(h).Encode(sessions) != nil {
		return fail()
	}
	post.files["database/"+sessionTable+".jsonl"] = hex.EncodeToString(h.Sum(nil))
	return intent, pending, post, nil
}

func (p sessionIntent) auditRow() [][]byte {
	at, _ := time.Parse(time.RFC3339Nano, p.CreatedAt)
	return [][]byte{[]byte(p.AuditID), []byte("controller-migration"), []byte("migration.sessions_revoked"), []byte(p.OperationID), []byte(at.UTC().Format("2006-01-02 15:04:05.000000"))}
}

// PlanSessionRevocation is read-only. The installed coordinator MUST persist
// these exact bytes in an exclusive, fsynced, protected journal before Apply.
// Caller-bound hashes are not substitutes for actual material/seal validation.
func (a *Archive) PlanSessionRevocation(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding) ([]byte, error) {
	plan, owner, p, e := a.restoredProof(ctx, receipt, dsn, proof)
	if e != nil || db == nil {
		return nil, ErrInvalid
	}
	view, e := captureSessionView(ctx, db, nil, owner)
	if e != nil || !sameDatabaseView(view, a.originalView(plan, p)) {
		return nil, ErrInvalid
	}
	intent, _, _, e := a.sessionExpectation(ctx, plan, p, proof, binding, view.auditDDL)
	if e != nil {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(intent)
	if e != nil {
		return nil, ErrInvalid
	}
	return append(raw, '\n'), nil
}

func (a *Archive) readSessionIntent(ctx context.Context, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding, raw []byte) (sessionIntent, *databaseOwnership, databaseView, databaseView, databaseView, error) {
	fail := func() (sessionIntent, *databaseOwnership, databaseView, databaseView, databaseView, error) {
		return sessionIntent{}, nil, databaseView{}, databaseView{}, databaseView{}, ErrInvalid
	}
	plan, owner, p, e := a.restoredProof(ctx, receipt, dsn, proof)
	var intent sessionIntent
	if e != nil || len(raw) > 65536 || !bytes.HasSuffix(raw, []byte("\n")) || !canonicalRecord(bytes.TrimSuffix(raw, []byte("\n")), &intent) {
		return fail()
	}
	want, pending, post, e := a.sessionExpectation(ctx, plan, p, proof, binding, intent.AuditBeforeDDL)
	if e != nil || !reflect.DeepEqual(intent, want) {
		return fail()
	}
	return intent, owner, a.originalView(plan, p), pending, post, nil
}

func sessionReport(intent sessionIntent, readOnly bool) SessionRevocationReport {
	return SessionRevocationReport{Schema: 1, OperationID: intent.OperationID, RevokedSessions: intent.SourceSessions,
		SessionsRevoked: true, AuditAppended: true, ExactDatabaseVerified: true, ReadOnlyVerification: readOnly}
}

// VerifyRevokedSessions resolves unknown commit outcomes without any SQL
// writes. Old sessions and arbitrary audit/metadata changes are never ignored.
func (a *Archive) VerifyRevokedSessions(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding, intent []byte) (SessionRevocationReport, error) {
	p, owner, _, _, post, e := a.readSessionIntent(ctx, receipt, dsn, proof, binding, intent)
	if e != nil || db == nil {
		return SessionRevocationReport{}, ErrInvalid
	}
	have, e := captureSessionView(ctx, db, nil, owner)
	if e != nil || !sameDatabaseView(have, post) {
		return SessionRevocationReport{}, ErrInvalid
	}
	return sessionReport(p, true), nil
}

// ApplySessionRevocation requires the exact restored preimage. Reentry after
// any attempted transaction must use read-only status first. It never assumes
// an error means rollback or automatically retries an unknown commit.
func (a *Archive) ApplySessionRevocation(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding, intent []byte) (SessionRevocationReport, error) {
	return a.changeSessions(ctx, db, receipt, dsn, proof, binding, intent, false)
}

// ResumeSessionRevocation is an explicit same-intent recovery operation. It
// additionally accepts precisely the original rows with the approved one-step
// audit counter advance after rollback; no other metadata/row drift is allowed.
// A completed postimage is NOT replayed: use VerifyRevokedSessions instead.
func (a *Archive) ResumeSessionRevocation(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding, intent []byte) (SessionRevocationReport, error) {
	return a.changeSessions(ctx, db, receipt, dsn, proof, binding, intent, true)
}

func (a *Archive) changeSessions(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, binding SessionTransitionBinding, raw []byte, resume bool) (SessionRevocationReport, error) {
	fail := func() (SessionRevocationReport, error) { return SessionRevocationReport{}, ErrInvalid }
	p, owner, before, pending, after, e := a.readSessionIntent(ctx, receipt, dsn, proof, binding, raw)
	if e != nil || db == nil {
		return fail()
	}
	conn, e := db.Conn(ctx)
	if e != nil {
		return fail()
	}
	defer conn.Close()
	defer discardConnection(conn)
	var acquired []string
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := len(acquired) - 1; i >= 0; i-- {
			_, _ = conn.ExecContext(c, "DO RELEASE_LOCK(?)", acquired[i])
		}
	}()
	// Duplicate attempts of this same operation still fail immediately. The
	// schema guard is server-wide and is also used by other controller databases:
	// wait with the same bounded budget as Migrate/SnapshotDatabase, before any
	// transaction or write, rather than rejecting a momentarily busy schema.
	// This is one lock acquisition, not a retry of the session transition.
	for _, lock := range []struct {
		name string
		wait int
	}{{"aster_restore_" + p.OperationID, 0}, {"aster_controller_schema_v1", 5}} {
		var locked int
		if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,?)", lock.name, lock.wait).Scan(&locked) != nil || locked != 1 {
			return fail()
		}
		acquired = append(acquired, lock.name)
	}
	for _, q := range []string{"SET SESSION information_schema_stats_expiry=0", "SET SESSION sql_quote_show_create=1",
		"SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO'", "SET SESSION foreign_key_checks=1"} {
		if _, e := conn.ExecContext(ctx, q); e != nil {
			return fail()
		}
	}
	tx, e := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return fail()
	}
	defer tx.Rollback()
	var id int
	if tx.QueryRowContext(ctx, "SELECT id FROM controller_identity_lock WHERE id=1 FOR UPDATE").Scan(&id) != nil || id != 1 {
		return fail()
	}
	have, e := captureSessionView(ctx, nil, tx, owner)
	if e != nil || !sameDatabaseView(have, before) && !(resume && sameDatabaseView(have, pending)) {
		return fail()
	}
	result, e := tx.ExecContext(ctx, "DELETE FROM controller_console_sessions")
	if e != nil {
		return fail()
	}
	deleted, e := result.RowsAffected()
	if e != nil || deleted != p.SourceSessions {
		return fail()
	}
	row := p.auditRow()
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_identity_audit(id,actor,action,target,created_at) VALUES(?,?,?,?,?)", row[0], row[1], row[2], row[3], row[4]); e != nil {
		return fail()
	}
	have, e = captureSessionView(ctx, nil, tx, owner)
	if e != nil || !sameDatabaseView(have, after) {
		return fail()
	}
	if tx.Commit() != nil {
		return fail()
	}
	return sessionReport(p, false), nil
}
