package controllerbackup

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerhost"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// TargetDatabasePlan is derived only from fixed private input, the exact
// installation and a durable admission seal. It exposes no password or source
// path. A data plan does not approve activation, even after provisioning.
type TargetDatabasePlan struct {
	Schema           int          `json:"schema"`
	Protocol         string       `json:"protocol"`
	ControllerID     string       `json:"controller_id"`
	OperationID      string       `json:"operation_id"`
	TargetPlanSHA256 string       `json:"target_plan_sha256"`
	Database         string       `json:"database"`
	RuntimeUser      string       `json:"runtime_user"`
	MigrationUser    string       `json:"migration_user"`
	Data             DatabasePlan `json:"data"`
}

func withTargetArchive(operation string, action func(TargetPlan, string, *Archive) error) error {
	plan, e := PlanTarget(operation)
	if e != nil {
		return e
	}
	dir := filepath.Join(targetRoot, operation)
	raw, e := targetRead(filepath.Join(dir, "plan.json"), 4096)
	var approved TargetPlan
	if e != nil || !exactSourceRecord(raw, &approved) || approved != plan {
		return ErrInvalid
	}
	canonical, e := json.Marshal(approved)
	if e != nil {
		return ErrInvalid
	}
	planSHA := digestBytes(canonical)
	if _, e = targetRead(filepath.Join("/var/lib/aster-controller", plan.ControllerID, "target-restore.json"), 4096); e != nil {
		return ErrInvalid
	}
	host, e := controllerhost.Open(plan.ControllerID, plan.CanonicalConfigurationSHA256)
	if e != nil {
		return e
	}
	defer host.Close()
	return host.WithSealedTarget(operation, planSHA, func() error {
		return WithVerifiedArchive(filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key"), plan.ControllerID, operation, dir, func(a *Archive) error {
			if _, e := a.ValidateSource(plan.SourceCommit); e != nil {
				return e
			}
			if hash, e := targetHash(filepath.Join(dir, "backup.age")); e != nil || hash != plan.ArchiveSHA256 {
				return ErrInvalid
			}
			return action(plan, planSHA, a)
		})
	})
}

func PlanTargetDatabase(ctx context.Context, operation string) (TargetDatabasePlan, error) {
	var result TargetDatabasePlan
	err := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		data, err := a.PlanDatabase(ctx)
		if err != nil {
			return err
		}
		// MySQL account contract is at most 31 characters. Full operation
		// binding remains in the immutable plan/receipt; collisions are refused.
		result = TargetDatabasePlan{1, "aster.controller-target-database/1", plan.ControllerID, operation, sha,
			"aster_cloud_restore_" + operation, "aster_r_" + operation[:23], "aster_m_" + operation[:23], data}
		return nil
	})
	if err != nil {
		return TargetDatabasePlan{}, err
	}
	return result, nil
}

// CheckTargetProvision proves both retained private credentials still reach
// the independently provisioned marker. The Python root coordinator separately
// verifies global account inventory, exact grants and root-visible objects.
func CheckTargetProvision(ctx context.Context, operation string) (map[string]bool, error) {
	err := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		db, e := loadTargetDatabase(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		return checkTargetAccounts(ctx, db)
	})
	if err != nil {
		return nil, err
	}
	return map[string]bool{"database_provisioned": true, "target_credentials_verified": true,
		"database_restored": false, "target_restore_approved": false, "migration_ready": false}, nil
}

type targetDatabase struct {
	plan         TargetDatabasePlan
	ownerRaw     []byte
	runtimeDSN   string
	migrationDSN string
}

func loadTargetDatabase(ctx context.Context, a *Archive, plan TargetPlan, sha string) (targetDatabase, error) {
	data, e := a.PlanDatabase(ctx)
	if e != nil {
		return targetDatabase{}, e
	}
	operation := plan.OperationID
	want := TargetDatabasePlan{1, "aster.controller-target-database/1", plan.ControllerID, operation, sha,
		"aster_cloud_restore_" + operation, "aster_r_" + operation[:23], "aster_m_" + operation[:23], data}
	dir := filepath.Join(targetRoot, operation)
	raw, e := targetRead(filepath.Join(dir, "database-plan.json"), 16384)
	var approved TargetDatabasePlan
	if e != nil || !exactSourceRecord(raw, &approved) || !reflect.DeepEqual(approved, want) {
		return targetDatabase{}, ErrInvalid
	}
	dir = filepath.Join(dir, "database")
	ownerRaw, e := targetRead(filepath.Join(dir, "mysql-provision.json"), 65536)
	if e != nil {
		return targetDatabase{}, e
	}
	db := targetDatabase{plan: want, ownerRaw: ownerRaw}
	for i, user := range []string{want.RuntimeUser, want.MigrationUser} {
		role := "runtime"
		if i == 1 {
			role = "migration"
		}
		raw, e := targetRead(filepath.Join(dir, role+"-mysql-dsn"), 4096)
		if e != nil {
			return targetDatabase{}, e
		}
		dsn := strings.TrimSpace(string(raw))
		cfg, e := mysql.ParseDSN(dsn)
		if e != nil || cfg.User != user || cfg.DBName != want.Database || cfg.Net != "unix" || cfg.Addr != "/run/mysqld/mysqld.sock" || len(cfg.Passwd) < 16 ||
			dsn != user+":"+cfg.Passwd+"@unix(/run/mysqld/mysqld.sock)/"+want.Database {
			return targetDatabase{}, ErrInvalid
		}
		if i == 0 {
			db.runtimeDSN = dsn
		} else {
			db.migrationDSN = dsn
		}
	}
	owner, e := restoreOwner(ownerRaw, db.runtimeDSN)
	if e != nil || owner.MigrationUser != want.MigrationUser {
		return targetDatabase{}, ErrInvalid
	}
	return db, nil
}
func checkTargetAccounts(ctx context.Context, db targetDatabase) error {
	owner, e := restoreOwner(db.ownerRaw, db.runtimeDSN)
	if e != nil {
		return e
	}
	for i, dsn := range []string{db.runtimeDSN, db.migrationDSN} {
		user := db.plan.RuntimeUser
		if i == 1 {
			user = db.plan.MigrationUser
		}
		store, e := control.OpenDSN(dsn)
		if e != nil {
			return ErrInvalid
		}
		e = func() error {
			defer store.DB.Close()
			conn, e := store.DB.Conn(ctx)
			if e != nil {
				return ErrInvalid
			}
			defer conn.Close()
			var account string
			if conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil || account != user+"@localhost" {
				return ErrInvalid
			}
			return verifyDatabaseOwnership(ctx, conn, owner, DatabaseSchema{1, db.plan.Data.Charset, db.plan.Data.Collation})
		}()
		if e != nil {
			return ErrInvalid
		}
	}
	return nil
}
