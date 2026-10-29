package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// VerificationSQLPolicy describes fixed grants for an already owned, sealed
// target. It does not create users, authenticate a restore journal, or authorize
// host startup. The root coordinator must independently bind the full operation.
type VerificationSQLPolicy struct {
	Database string   `json:"database"`
	User     string   `json:"user"`
	Grants   []string `json:"grants"`
}

var verificationDatabaseName = regexp.MustCompile(`^aster_[a-z0-9_]{1,58}$`)
var verificationMySQLVersion = regexp.MustCompile(`^8\.(0|4)\.([0-9]+)(?:[-+].*)?$`)

func VerificationDatabasePolicy(database, operation string) (VerificationSQLPolicy, error) {
	if !verificationDatabaseName.MatchString(database) || !validID(operation) {
		return VerificationSQLPolicy{}, ErrInput
	}
	user := "aster_v_" + operation[:23]
	account := "`" + user + "`@`localhost`"
	// Schema grants have wildcard semantics even inside backticks. Table-level
	// database names are literal: escaping them would address a different schema.
	schema := "`" + strings.ReplaceAll(database, "_", `\_`) + "`.*"
	table := "`" + database + "`."
	return VerificationSQLPolicy{Database: database, User: user, Grants: []string{
		"GRANT SELECT ON " + schema + " TO " + account,
		"GRANT INSERT, DELETE ON " + table + "`controller_console_sessions` TO " + account,
		"GRANT INSERT, UPDATE, DELETE ON " + table + "`controller_console_login_limits` TO " + account,
		"GRANT INSERT (`actor`, `action`, `target`, `created_at`) ON " + table + "`controller_identity_audit` TO " + account,
	}}, nil
}

// CheckVerificationSQLIdentity verifies the actual connection identity and all
// effective grant sources, not just the expected username or a receipt flag.
// No credential, SQL, grant or schema is changed to make this check pass.
func CheckVerificationSQLIdentity(ctx context.Context, db *sql.DB, operation string) (VerificationSQLPolicy, error) {
	fail := func() (VerificationSQLPolicy, error) { return VerificationSQLPolicy{}, ErrInput }
	if db == nil || !validID(operation) {
		return fail()
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fail()
	}
	defer conn.Close()
	var account, database, version, mandatory, roles string
	var partial int
	if conn.QueryRowContext(ctx, "SELECT CURRENT_USER(),DATABASE(),VERSION(),@@partial_revokes,@@mandatory_roles,CURRENT_ROLE()").Scan(&account, &database, &version, &partial, &mandatory, &roles) != nil {
		return fail()
	}
	policy, err := VerificationDatabasePolicy(database, operation)
	v := verificationMySQLVersion.FindStringSubmatch(version)
	if err != nil || account != policy.User+"@localhost" || partial != 0 || mandatory != "" || roles != "NONE" || len(v) != 3 {
		return fail()
	}
	patch, err := strconv.Atoi(v[2])
	if err != nil || v[1] == "0" && patch < 22 {
		return fail()
	}
	rows, err := conn.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
	if err != nil {
		return fail()
	}
	defer rows.Close()
	seen := map[string]bool{}
	suffix := " TO `" + policy.User + "`@`localhost`"
	schema := "`" + strings.ReplaceAll(database, "_", `\_`) + "`.*"
	tables := "`" + database + "`."
	for rows.Next() {
		var line string
		if rows.Scan(&line) != nil || len(line) > 4096 || !strings.HasPrefix(line, "GRANT ") || !strings.HasSuffix(line, suffix) {
			return fail()
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "GRANT "), suffix), " ON ")
		if len(parts) != 2 || seen[parts[1]] {
			return fail()
		}
		object, privileges := parts[1], parts[0]
		valid := false
		switch object {
		case "*.*":
			valid = privileges == "USAGE"
		case schema:
			valid = privileges == "SELECT"
		case tables + "`controller_console_sessions`":
			valid = verificationGrantSet(privileges, "DELETE, INSERT")
		case tables + "`controller_console_login_limits`":
			valid = verificationGrantSet(privileges, "DELETE, INSERT, UPDATE")
		case tables + "`controller_identity_audit`":
			if strings.HasPrefix(privileges, "INSERT (") && strings.HasSuffix(privileges, ")") {
				columns := strings.TrimSuffix(strings.TrimPrefix(privileges, "INSERT ("), ")")
				valid = verificationGrantSet(columns, "`action`, `actor`, `created_at`, `target`")
			}
		}
		if !valid {
			return fail()
		}
		seen[object] = true
	}
	if rows.Err() != nil || len(seen) != 5 {
		return fail()
	}
	return policy, nil
}

func verificationGrantSet(value, want string) bool {
	parts := strings.Split(value, ", ")
	sort.Strings(parts)
	return strings.Join(parts, ", ") == want
}

// NewVerification binds authentication to the same narrowly privileged SQL
// connection used by verification resource reads. It never bootstraps an admin.
func NewVerification(ctx context.Context, db *sql.DB, cfg Config, operation string) (*Service, error) {
	policy, err := CheckVerificationSQLIdentity(ctx, db, operation)
	if err != nil {
		return nil, err
	}
	service, err := New(db, cfg)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(policy.Database))
	service.verificationLock = "aster_verify_identity_" + hex.EncodeToString(digest[:16])
	return service, nil
}
