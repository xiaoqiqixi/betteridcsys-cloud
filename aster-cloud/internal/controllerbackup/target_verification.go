package controllerbackup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"aster/cloud/internal/control"
	"aster/cloud/internal/identity"

	"github.com/go-sql-driver/mysql"
)

// TargetVerificationPlan binds the only permitted SQL identity to a freshly
// verified sealed target and its published configuration. It is not a grant to
// create an account or start a process, and contains neither a DSN nor secrets.
type TargetVerificationPlan struct {
	Schema                    int                            `json:"schema"`
	Protocol                  string                         `json:"protocol"`
	ControllerID              string                         `json:"controller_id"`
	OperationID               string                         `json:"operation_id"`
	TargetPlanSHA256          string                         `json:"target_plan_sha256"`
	ConfigurationPlanSHA256   string                         `json:"configuration_plan_sha256"`
	ConfigurationIntentSHA256 string                         `json:"configuration_intent_sha256"`
	SessionIntentSHA256       string                         `json:"session_intent_sha256"`
	ConsoleOrigin             string                         `json:"console_origin"`
	Listen                    string                         `json:"listen"`
	SQL                       identity.VerificationSQLPolicy `json:"sql"`
}

type TargetVerificationPlanReport struct {
	Schema                 int                    `json:"schema"`
	OperationID            string                 `json:"operation_id"`
	Plan                   TargetVerificationPlan `json:"plan"`
	PlanSHA256             string                 `json:"plan_sha256"`
	ReadOnly               bool                   `json:"readonly"`
	ExactDatabaseVerified  bool                   `json:"exact_database_verified"`
	ConfigurationPublished bool                   `json:"configuration_published"`
	SQLIdentityPrepared    bool                   `json:"sql_identity_prepared"`
	ServiceStarted         bool                   `json:"service_started"`
	MigrationReady         bool                   `json:"migration_ready"`
}

// No caller-supplied paths, DSNs, SQL or configuration proofs reach this fixed
// root entry. Verification login is not yet allowed: the original complete
// post-revocation SQL image must still match, including all three auth tables.
func PlanTargetVerification(ctx context.Context, operation string) (TargetVerificationPlanReport, error) {
	var result TargetVerificationPlanReport
	err := withTargetVerification(ctx, operation, func(report TargetVerificationPlanReport, _ RuntimeTarget) error {
		result = report
		return nil
	})
	if err != nil {
		return TargetVerificationPlanReport{}, err
	}
	return result, nil
}

func withTargetVerification(ctx context.Context, operation string, action func(TargetVerificationPlanReport, RuntimeTarget) error) error {
	return withTargetArchiveMode(operation, true, func(plan TargetPlan, sha string, a *Archive) error {
		runtime, request, sessionSHA, e := targetConfigurationInputs(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		bound, planSHA, e := publishedVerificationPlan(a, plan, sha, runtime, request, sessionSHA)
		if e != nil {
			return ErrInvalid
		}
		report := TargetVerificationPlanReport{Schema: 1, OperationID: operation, Plan: bound, PlanSHA256: planSHA, ReadOnly: true, ExactDatabaseVerified: true, ConfigurationPublished: true}
		return action(report, runtime)
	})
}

// The publication/endpoint binding is shared; callers must independently prove
// their exact SQL phase. This helper never claims an unchanged database.
func publishedVerificationPlan(a *Archive, plan TargetPlan, sha string, runtime RuntimeTarget, request []byte, sessionSHA string) (TargetVerificationPlan, string, error) {
	fail := func() (TargetVerificationPlan, string, error) { return TargetVerificationPlan{}, "", ErrInvalid }
	approval, e := targetRead(filepath.Join(runtime.Directory, "configuration-approval.json"), 8192)
	if e != nil {
		return fail()
	}
	publication, e := a.VerifyPublishedConfiguration(ConfigurationPublicationTarget{Runtime: runtime, ParentDirectory: "/etc"}, request, approval, sessionSHA)
	if e != nil || !publication.Plan.ConsoleEnabled || publication.Plan.ConsoleOrigin == "" {
		return fail()
	}
	policy, e := identity.VerificationDatabasePolicy("aster_cloud_restore_"+plan.OperationID, plan.OperationID)
	if e != nil {
		return fail()
	}
	bound := TargetVerificationPlan{1, "aster.controller-verification-plan/1", plan.ControllerID, plan.OperationID, sha, publication.PlanSHA256, publication.IntentSHA256, sessionSHA, publication.Plan.ConsoleOrigin, publication.Plan.Listen, policy}
	raw, e := json.Marshal(bound)
	if e != nil {
		return fail()
	}
	return bound, digestBytes(raw), nil
}

// The root account writer cannot mark a credential ready merely because a file
// exists. This fixed read-only entry really authenticates it, checks all grants
// and the owned database marker under the same original archive/target seal.
func CheckTargetVerificationCredential(ctx context.Context, operation string) (map[string]any, error) {
	var result map[string]any
	err := withTargetVerification(ctx, operation, func(report TargetVerificationPlanReport, runtime RuntimeTarget) error {
		if _, err := targetVerificationCredential(ctx, operation, report.Plan, report.PlanSHA256, runtime); err != nil {
			return err
		}
		result = map[string]any{"schema": 1, "operation_id": operation, "plan_sha256": report.PlanSHA256, "credential_verified": true, "sql_identity_verified": true, "exact_database_verified": true, "service_started": false, "migration_ready": false}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// This check authenticates the precise saved least-privilege credential, but
// makes no SQL-image claim. Each caller must verify its own complete data phase
// under the target seal; the legacy entry retains its exact zero-session image.
func targetVerificationCredential(ctx context.Context, operation string, plan TargetVerificationPlan, planSHA string, runtime RuntimeTarget) (string, error) {
	directory := filepath.Join(runtime.Directory, "database")
	for _, name := range []string{"verification-revoke-started.json", "verification-revoked.json"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			return "", ErrInvalid
		}
	}
	raw, e := targetRead(filepath.Join(directory, "verification-started.json"), 8192)
	if e != nil {
		return "", e
	}
	var intent struct {
		Schema      int    `json:"schema"`
		OperationID string `json:"operation_id"`
		PlanSHA256  string `json:"plan_sha256"`
		Database    string `json:"database"`
		User        string `json:"user"`
		ServerUUID  string `json:"server_uuid"`
		OwnerSHA256 string `json:"owner_sha256"`
		Charset     string `json:"charset"`
		Collation   string `json:"collation"`
		Nonce       string `json:"nonce"`
	}
	if !exactSourceRecord(raw, &intent) || intent.Schema != 1 || intent.OperationID != operation || intent.PlanSHA256 != planSHA || intent.Database != plan.SQL.Database || intent.User != plan.SQL.User || !shaPattern.MatchString(intent.Nonce) {
		return "", ErrInvalid
	}
	ownerRaw, e := targetRead(filepath.Join(directory, "mysql-provision.json"), 65536)
	if e != nil || digestBytes(ownerRaw) != intent.OwnerSHA256 {
		return "", ErrInvalid
	}
	owner, e := restoreOwner(ownerRaw, runtime.DSN)
	if e != nil || owner.ServerUUID != intent.ServerUUID {
		return "", ErrInvalid
	}
	credential, e := targetRead(filepath.Join(directory, "verification-mysql-dsn"), 4096)
	if e != nil {
		return "", e
	}
	dsn := strings.TrimSuffix(string(credential), "\n")
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil || cfg.User != intent.User || cfg.DBName != intent.Database || cfg.Net != "unix" || cfg.Addr != "/run/mysqld/mysqld.sock" || len(cfg.Passwd) < 16 || len(cfg.Passwd) > 1024 ||
		string(credential) != cfg.User+":"+cfg.Passwd+"@unix(/run/mysqld/mysqld.sock)/"+cfg.DBName+"\n" {
		return "", ErrInvalid
	}
	store, e := control.OpenDSN(dsn)
	if e != nil {
		return "", ErrInvalid
	}
	defer store.DB.Close()
	policy, e := identity.CheckVerificationSQLIdentity(ctx, store.DB, operation)
	if e != nil || !reflect.DeepEqual(policy, plan.SQL) {
		return "", ErrInvalid
	}
	conn, e := store.DB.Conn(ctx)
	if e != nil {
		return "", ErrInvalid
	}
	defer conn.Close()
	if verifyDatabaseOwnership(ctx, conn, owner, DatabaseSchema{1, intent.Charset, intent.Collation}) != nil {
		return "", ErrInvalid
	}
	return dsn, nil
}
