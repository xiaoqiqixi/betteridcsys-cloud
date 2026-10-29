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
	"time"
)

const loginLimitTable = "controller_console_login_limits"

// VerificationDataBinding comes from an independently protected host approval.
// These hashes do not by themselves prove that a host or SQL account is safe.
// A verification interval is explicit and bounded; it never authorizes takeover.
type VerificationDataBinding struct {
	VerificationPlanSHA256 string
	AccountReceiptSHA256   string
	StartedAt              time.Time
	ExpiresAt              time.Time
}

type verificationDataIntent struct {
	Schema                 int    `json:"schema"`
	Protocol               string `json:"protocol"`
	OperationID            string `json:"operation_id"`
	ControllerID           string `json:"controller_id"`
	SessionIntentSHA256    string `json:"session_intent_sha256"`
	VerificationPlanSHA256 string `json:"verification_plan_sha256"`
	AccountReceiptSHA256   string `json:"account_receipt_sha256"`
	StartedAt              string `json:"started_at"`
	ExpiresAt              string `json:"expires_at"`
}

type VerificationDataReport struct {
	Schema                      int    `json:"schema"`
	OperationID                 string `json:"operation_id"`
	PhaseIntentSHA256           string `json:"phase_intent_sha256"`
	BusinessDataUnchanged       bool   `json:"business_data_unchanged"`
	HistoricalAuditPreserved    bool   `json:"historical_audit_preserved"`
	AuthenticationDataValidated bool   `json:"authentication_data_validated"`
	ReadOnlyVerification        bool   `json:"read_only_verification"`
	CurrentSessions             int64  `json:"current_sessions"`
	CurrentLoginBuckets         int64  `json:"current_login_buckets"`
	AppendedAuditRows           int64  `json:"appended_audit_rows"`
	TargetActivationApproved    bool   `json:"target_activation_approved"`
	MigrationReady              bool   `json:"migration_ready"`
}

func verificationPhaseIntent(p sessionIntent, raw []byte, b VerificationDataBinding) ([]byte, error) {
	_, startOffset := b.StartedAt.Zone()
	_, endOffset := b.ExpiresAt.Zone()
	sessionAt, e := time.Parse(time.RFC3339Nano, p.CreatedAt)
	if e != nil || !shaPattern.MatchString(b.VerificationPlanSHA256) || !shaPattern.MatchString(b.AccountReceiptSHA256) ||
		startOffset != 0 || endOffset != 0 || b.StartedAt.Year() < 2000 || b.ExpiresAt.Year() > 9999 ||
		b.StartedAt.Nanosecond()%1000 != 0 || b.ExpiresAt.Nanosecond()%1000 != 0 || b.StartedAt.Before(sessionAt) ||
		!b.ExpiresAt.After(b.StartedAt) || b.ExpiresAt.Sub(b.StartedAt) > time.Hour {
		return nil, ErrInvalid
	}
	value := verificationDataIntent{1, "aster.controller-verification-data/1", p.OperationID, p.ControllerID,
		digestBytes(raw), b.VerificationPlanSHA256, b.AccountReceiptSHA256,
		b.StartedAt.Format(time.RFC3339Nano), b.ExpiresAt.Format(time.RFC3339Nano)}
	encoded, e := json.Marshal(value)
	if e != nil {
		return nil, ErrInvalid
	}
	return append(encoded, '\n'), nil
}

// PlanVerificationDataPhase only accepts the original exact revoked image.
// The coordinator must durably persist these bytes BEFORE admitting login.
// It never adopts already modified authentication tables as a new baseline.
func (a *Archive) PlanVerificationDataPhase(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, sessions SessionTransitionBinding, sessionIntentRaw []byte, binding VerificationDataBinding) ([]byte, error) {
	p, owner, _, _, post, e := a.readSessionIntent(ctx, receipt, dsn, proof, sessions, sessionIntentRaw)
	if e != nil || db == nil {
		return nil, ErrInvalid
	}
	intent, e := verificationPhaseIntent(p, sessionIntentRaw, binding)
	if e != nil {
		return nil, ErrInvalid
	}
	have, e := captureSessionView(ctx, db, nil, owner)
	if e != nil || !sameDatabaseView(have, post) {
		return nil, ErrInvalid
	}
	return intent, nil
}

// VerifyVerificationDataPhase is a data proof, not a running-service permit.
// The host coordinator must independently stop/drain authentication and retain
// the original seal before using this proof to progress. No table is omitted:
// business rows/DDL remain exact, old audit bytes remain exact, and only bounded
// authentication records with approved shapes/actions/times may differ.
func (a *Archive) VerifyVerificationDataPhase(ctx context.Context, db *sql.DB, receipt []byte, dsn string, proof []byte, sessions SessionTransitionBinding, sessionIntentRaw []byte, binding VerificationDataBinding, intent []byte) (VerificationDataReport, error) {
	fail := func() (VerificationDataReport, error) { return VerificationDataReport{}, ErrInvalid }
	p, owner, _, _, post, e := a.readSessionIntent(ctx, receipt, dsn, proof, sessions, sessionIntentRaw)
	if e != nil || db == nil {
		return fail()
	}
	want, e := verificationPhaseIntent(p, sessionIntentRaw, binding)
	if e != nil || !bytes.Equal(want, intent) {
		return fail()
	}
	checker, e := a.verificationDataChecker(ctx, p, post, binding)
	if e != nil {
		return fail()
	}
	have := databaseView{files: map[string]string{}}
	write := func(name string, emit func(io.Writer) error) error {
		if name != "database/"+sessionTable+".jsonl" && name != "database/"+loginLimitTable+".jsonl" && name != "database/"+identityAuditTable+".jsonl" {
			return viewWriter(&have)(name, emit)
		}
		return checker.table(name, emit, &have)
	}
	have.rows, e = snapshotDatabaseChecked(ctx, db, owner, write, func(q sqlReader) error { return viewStructure(ctx, q, owner, &have) })
	if e != nil {
		return fail()
	}
	// Every mutable row was parsed, not dropped from the total or silently
	// excluded. Only their independently validated projections compare to post.
	have.rows -= checker.sessions + checker.auditAdded + checker.limits - checker.originalLimits
	if !sameDatabaseView(have, post) {
		return fail()
	}
	return VerificationDataReport{Schema: 1, OperationID: p.OperationID, PhaseIntentSHA256: digestBytes(intent),
		BusinessDataUnchanged: true, HistoricalAuditPreserved: true, AuthenticationDataValidated: true,
		ReadOnlyVerification: true, CurrentSessions: checker.sessions, CurrentLoginBuckets: checker.limits, AppendedAuditRows: checker.auditAdded}, nil
}

type verificationDataCheck struct {
	binding                                      VerificationDataBinding
	session                                      sessionIntent
	post                                         databaseView
	headers                                      map[string]Table
	users                                        map[string]bool
	oldTokens                                    map[string]bool
	oldLimits                                    map[string]verificationLoginBucket
	originalLimits, sessions, limits, auditAdded int64
	firstNewAudit                                int64
}

type verificationLoginBucket struct {
	digest, window, attempts string
	seen                     bool
}

func (a *Archive) verificationDataChecker(ctx context.Context, p sessionIntent, post databaseView, binding VerificationDataBinding) (*verificationDataCheck, error) {
	c := &verificationDataCheck{binding: binding, session: p, post: post, headers: map[string]Table{}, users: map[string]bool{}, oldTokens: map[string]bool{}, oldLimits: map[string]verificationLoginBucket{}}
	id, e := strconv.ParseInt(p.AuditID, 10, 64)
	if e != nil || id < 1 || id >= math.MaxInt64 {
		return nil, ErrInvalid
	}
	c.firstNewAudit = id + 1
	// This is a validation-memory budget, never a truncation or a lifetime
	// operation count. Oversized inputs fail closed with no writes.
	budget := 64 << 20
	charge := func(n int) error {
		budget -= n
		if budget < 0 {
			return ErrInvalid
		}
		return nil
	}
	for _, name := range []string{sessionTable, loginLimitTable, identityAuditTable} {
		_, e = a.tableRecords(ctx, name, func(t Table) error { c.headers[name] = t; return nil }, func(row [][]byte) error {
			switch name {
			case sessionTable:
				if len(row) != 4 || len(row[0]) != 32 || charge(128) != nil {
					return ErrInvalid
				}
				c.oldTokens[string(row[0])] = true
			case loginLimitTable:
				if len(row) != 3 || len(row[0]) != 32 || charge(512) != nil {
					return ErrInvalid
				}
				raw, e := json.Marshal(row)
				if e != nil {
					return ErrInvalid
				}
				c.oldLimits[string(row[0])] = verificationLoginBucket{digest: digestBytes(raw), window: string(row[1]), attempts: string(row[2])}
				c.originalLimits++
			}
			return nil
		})
		if e != nil {
			return nil, ErrInvalid
		}
	}
	var idIndex, enabledIndex = -1, -1
	_, e = a.tableRecords(ctx, "controller_console_users", func(t Table) error {
		for i, col := range t.Columns {
			if col.Name == "id" {
				idIndex = i
			}
			if col.Name == "enabled" {
				enabledIndex = i
			}
		}
		if idIndex < 0 || enabledIndex < 0 {
			return ErrInvalid
		}
		return nil
	}, func(row [][]byte) error {
		id := string(row[idIndex])
		enabled := string(row[enabledIndex])
		if !operationID.MatchString(id) || (enabled != "0" && enabled != "1") || charge(128) != nil {
			return ErrInvalid
		}
		c.users[id] = enabled == "1"
		return nil
	})
	if e != nil {
		return nil, ErrInvalid
	}
	return c, nil
}

func verificationTime(raw []byte) (time.Time, error) {
	at, e := time.Parse("2006-01-02 15:04:05.000000", string(raw))
	if e != nil || at.Format("2006-01-02 15:04:05.000000") != string(raw) {
		return time.Time{}, ErrInvalid
	}
	return at, nil
}

func (c *verificationDataCheck) within(raw []byte) bool {
	at, e := verificationTime(raw)
	return e == nil && !at.Before(c.binding.StartedAt) && at.Before(c.binding.ExpiresAt)
}

// Stream one bounded record at a time; audit history is never buffered as a
// whole, truncated to a page, or copied into the public result.
type verificationRecordWriter struct {
	pending []byte
	record  func([]byte) error
}

func (w *verificationRecordWriter) Write(raw []byte) (int, error) {
	total := len(raw)
	for len(raw) > 0 {
		end := bytes.IndexByte(raw, '\n')
		part := raw
		if end >= 0 {
			part = raw[:end]
		}
		if len(w.pending)+len(part) > 65<<20 {
			return 0, ErrInvalid
		}
		w.pending = append(w.pending, part...)
		if end < 0 {
			return total, nil
		}
		if w.record(w.pending) != nil {
			return 0, ErrInvalid
		}
		w.pending = w.pending[:0]
		raw = raw[end+1:]
	}
	return total, nil
}

func (c *verificationDataCheck) table(path string, emit func(io.Writer) error, view *databaseView) error {
	name := path[len("database/") : len(path)-len(".jsonl")]
	expected := c.headers[name]
	prefix := sha256.New()
	encoder := json.NewEncoder(prefix)
	headerSeen := false
	var nextAudit, lastAudit int64
	auditSeen := false
	reader := &verificationRecordWriter{record: func(raw []byte) error {
		if !headerSeen {
			var header Table
			if len(raw) > 256<<10 || !canonicalRecord(raw, &header) || !validTable(header, name) {
				return ErrInvalid
			}
			if name == identityAuditTable {
				if header.NextID == nil {
					return ErrInvalid
				}
				var e error
				nextAudit, e = strconv.ParseInt(*header.NextID, 10, 64)
				if e != nil || nextAudit < c.firstNewAudit || nextAudit >= math.MaxInt64 {
					return ErrInvalid
				}
				ddl, e := advancedAuditDDL(c.session.AuditBeforeDDL, c.session.AuditID, *header.NextID)
				if e != nil || ddl != view.auditDDL {
					return ErrInvalid
				}
				// Exact DDL except the authentication audit's checked high water.
				for i := range view.structure {
					if view.structure[i].Name == identityAuditTable {
						for _, p := range c.post.structure {
							if p.Name == identityAuditTable {
								view.structure[i].SHA256 = p.SHA256
							}
						}
					}
				}
				base := strconv.FormatInt(c.firstNewAudit, 10)
				header.NextID = &base
				expected.NextID = &base
				if encoder.Encode(header) != nil {
					return ErrInvalid
				}
			}
			if !reflect.DeepEqual(header, expected) {
				return ErrInvalid
			}
			headerSeen = true
			return nil
		}
		var row [][]byte
		if !canonicalRecord(raw, &row) || len(row) != len(expected.Columns) {
			return ErrInvalid
		}
		for i, col := range expected.Columns {
			if row[i] == nil && col.Nullable != "YES" {
				return ErrInvalid
			}
		}
		switch name {
		case sessionTable:
			if len(row) != 4 || len(row[0]) != 32 || c.oldTokens[string(row[0])] || !c.within(row[2]) {
				return ErrInvalid
			}
			if row[1] != nil && !c.users[string(row[1])] {
				return ErrInvalid
			}
			created, e := verificationTime(row[2])
			if e != nil {
				return ErrInvalid
			}
			expires, e := verificationTime(row[3])
			if e != nil || !expires.After(created) || expires.Sub(created) > 24*time.Hour {
				return ErrInvalid
			}
			if (row[1] == nil && expires.Sub(created) != 10*time.Minute) ||
				(row[1] != nil && expires.Sub(created) < 5*time.Minute) {
				return ErrInvalid
			}
			c.sessions++
		case loginLimitTable:
			if len(row) != 3 || len(row[0]) != 32 {
				return ErrInvalid
			}
			// The service increments a surviving 15-minute window without
			// changing window_at. A reset must wait for that original window
			// to expire; it cannot manufacture an earlier fresh allowance.
			old, existed := c.oldLimits[string(row[0])]
			if existed {
				old.seen = true
				c.oldLimits[string(row[0])] = old
			}
			if !existed || old.digest != digestBytes(raw) {
				n, e := strconv.ParseInt(string(row[2]), 10, 64)
				if e != nil || strconv.FormatInt(n, 10) != string(row[2]) || n < 1 || n > 4096 {
					return ErrInvalid
				}
				at, e := verificationTime(row[1])
				if e != nil {
					return ErrInvalid
				}
				if existed {
					before, e := verificationTime([]byte(old.window))
					if e != nil {
						return ErrInvalid
					}
					if at.Equal(before) {
						oldCount, e := strconv.ParseInt(old.attempts, 10, 64)
						if e != nil || oldCount < 0 || n < oldCount || !before.Before(c.binding.ExpiresAt) ||
							!c.binding.StartedAt.Before(before.Add(15*time.Minute)) {
							return ErrInvalid
						}
					} else if !c.within(row[1]) || at.Before(before.Add(15*time.Minute)) {
						return ErrInvalid
					}
				} else if !c.within(row[1]) {
					return ErrInvalid
				}
			}
			c.limits++
		case identityAuditTable:
			if len(row) != 5 {
				return ErrInvalid
			}
			id, e := strconv.ParseInt(string(row[0]), 10, 64)
			if e != nil || strconv.FormatInt(id, 10) != string(row[0]) || (auditSeen && id <= lastAudit) || id >= nextAudit {
				return ErrInvalid
			}
			lastAudit = id
			auditSeen = true
			if id < c.firstNewAudit {
				return encoder.Encode(row)
			}
			if !c.within(row[4]) {
				return ErrInvalid
			}
			switch string(row[2]) {
			case "identity.login", "identity.logout":
				if !c.users[string(row[1])] || !bytes.Equal(row[1], row[3]) {
					return ErrInvalid
				}
			case "identity.login_failed":
				if string(row[1]) != "anonymous" || !shaPattern.Match(row[3]) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
			c.auditAdded++
		default:
			return ErrInvalid
		}
		return nil
	}}
	if emit(reader) != nil || len(reader.pending) != 0 || !headerSeen {
		return ErrInvalid
	}
	if name == loginLimitTable {
		for _, old := range c.oldLimits {
			if old.seen {
				continue
			}
			at, e := verificationTime([]byte(old.window))
			// Authentication only prunes windows at least 24 hours old. A
			// missing live bucket must not silently become a fresh allowance.
			if e != nil || !at.Add(24*time.Hour).Before(c.binding.ExpiresAt) {
				return ErrInvalid
			}
		}
	}
	if name == identityAuditTable && hex.EncodeToString(prefix.Sum(nil)) != c.post.files[path] {
		return ErrInvalid
	}
	view.files[path] = c.post.files[path]
	return nil
}
