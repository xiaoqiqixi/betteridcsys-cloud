package controllerbackup

import (
	"aster/cloud/internal/control"
	"context"
	"os"
	"reflect"
	"regexp"

	"github.com/go-sql-driver/mysql"
)

const installerOwnershipTable = "aster_installer_ownership"

// This is a source-local provisioning receipt, not a transferable ownership
// capability. The target must create its own database and ownership evidence.
// It contains account names but never passwords or the runtime DSN.
type databaseOwnership struct {
	Schema        int      `json:"schema"`
	Database      string   `json:"database"`
	RuntimeUser   string   `json:"runtime_user"`
	MigrationUser string   `json:"migration_user"`
	ServerUUID    string   `json:"server_uuid"`
	Nonce         string   `json:"nonce"`
	Steps         []string `json:"steps"`
	Status        string   `json:"status"`
}

func sourceDatabaseOwnership(dsn string) (*databaseOwnership, []byte, error) {
	const path = "/var/lib/aster-cloud-installer/controller/mysql-provision.json"
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		// Imported/manual databases have no provisioning exception. Their
		// entire inventory must consist of exactly the embedded business tables.
		return nil, nil, nil
	}
	raw, e := control.ReadProtected(path, true, 65536)
	if e != nil {
		return nil, nil, ErrInvalid
	}
	var owner databaseOwnership
	account := regexp.MustCompile(`^aster_[a-z0-9_]{1,25}$`)
	uuid := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	config, e := mysql.ParseDSN(dsn)
	steps := []string{"database-created", "runtime-created", "runtime-granted", "migration-created", "migration-granted"}
	if e != nil || !strictRecord(raw, &owner) || owner.Schema != 1 || owner.Status != "dedicated-database-provisioned" ||
		!reflect.DeepEqual(owner.Steps, steps) || !sqlName.MatchString(owner.Database) || owner.Database != config.DBName ||
		!account.MatchString(owner.RuntimeUser) || !account.MatchString(owner.MigrationUser) || owner.RuntimeUser == owner.MigrationUser ||
		owner.RuntimeUser != config.User || !uuid.MatchString(owner.ServerUUID) || !shaPattern.MatchString(owner.Nonce) {
		return nil, nil, ErrInvalid
	}
	return &owner, raw, nil
}

// Called inside the same read-only snapshot transaction after metadata locks
// have been acquired. A table name alone is never grounds for an exception.
func verifyDatabaseOwnership(ctx context.Context, q sqlReader, owner *databaseOwnership, schema DatabaseSchema) error {
	var database, server string
	if q.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid").Scan(&database, &server) != nil || database != owner.Database || server != owner.ServerUUID {
		return ErrInvalid
	}
	t, e := describeTable(ctx, q, installerOwnershipTable)
	want := []Column{
		{Name: "id", Type: "int", Nullable: "NO", Key: "PRI"},
		{Name: "nonce", Type: "char(64)", Nullable: "NO", Charset: &schema.Charset, Collation: &schema.Collation},
		{Name: "server_uuid", Type: "char(36)", Nullable: "NO", Charset: &schema.Charset, Collation: &schema.Collation},
	}
	if e != nil || t.NextID != nil || t.Collation != schema.Collation || !reflect.DeepEqual(t.Columns, want) {
		return ErrInvalid
	}
	r, e := q.QueryContext(ctx, "SELECT id,nonce,server_uuid FROM aster_installer_ownership")
	if e != nil {
		return ErrInvalid
	}
	defer r.Close()
	var id int
	var nonce, uuid string
	if !r.Next() || r.Scan(&id, &nonce, &uuid) != nil || id != 1 || nonce != owner.Nonce || uuid != owner.ServerUUID || r.Next() || r.Err() != nil {
		return ErrInvalid
	}
	return nil
}
