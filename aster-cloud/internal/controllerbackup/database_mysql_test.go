package controllerbackup_test

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Real SQL is the agreed seam. No sqlmock, MySQL protocol imitation or source
// production database; the independently named test DB is created and removed
// only by the fixture which owns its nonce.
func TestMySQLMigrationSnapshotPreservesTypedBytes(t *testing.T) {
	dsn := os.Getenv("ASTER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("ASTER_MYSQL_TEST_DSN unset: real migration snapshot not run")
	}
	c, e := mysql.ParseDSN(dsn)
	if e != nil || c.DBName != "aster_ci_test" {
		t.Fatal("isolated native fixture required")
	}
	c.MultiStatements = false
	admin, e := sql.Open("mysql", c.FormatDSN())
	if e != nil {
		t.Fatal("fixture unavailable")
	}
	defer admin.Close()
	nonce := make([]byte, 12)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	name := "aster_cloud_test_backup_" + hex.EncodeToString(nonce)
	if _, e = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
		t.Fatal("fixture creation failed")
	}
	defer func() {
		if _, e := admin.Exec("DROP DATABASE `" + name + "`"); e != nil {
			t.Error("owned fixture cleanup failed")
		}
	}()
	c.DBName = name
	store, e := control.OpenDSN(c.FormatDSN())
	if e != nil {
		t.Fatal("fixture DSN invalid")
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if e = store.Migrate(ctx); e != nil {
		t.Fatal("migration failed", e)
	}
	stamp := "2026-10-28 01:02:03.123456"
	for _, row := range []struct {
		id  string
		raw []byte
	}{{"node-a", []byte{0, 255, 0, 10, 34, 92, 128}}, {"node-b", []byte{}}} {
		_, e = store.DB.ExecContext(ctx, "INSERT INTO controller_nodes(id,profile_sha256,datacenter_id,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities,updated_at) VALUES(?,?,?,0,NULL,9223372036854775806,0,0,?,?)", row.id, string(bytes.Repeat([]byte("a"), 64)), "香港", row.raw, stamp)
		if e != nil {
			t.Fatal("typed source fixture failed", e)
		}
	}
	// A deleted high ID must not be reused after restore. Also exercise a
	// real FK, binary session hash, JSON and an unsigned value above int64.
	if _, e = store.DB.ExecContext(ctx, "INSERT INTO controller_audit(id,actor,action,target,created_at) VALUES(41,'fixture','fixture','fixture',?)", stamp); e != nil {
		t.Fatal(e)
	}
	if _, e = store.DB.ExecContext(ctx, "DELETE FROM controller_audit WHERE id=41"); e != nil {
		t.Fatal(e)
	}
	userID := strings.Repeat("a", 32)
	if _, e = store.DB.ExecContext(ctx, "INSERT INTO controller_console_users(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at,revision) VALUES(?,?,?,'unusable-fixture-hash','admin',1,JSON_ARRAY(),?,?,18446744073709551614)", userID, "restore-fixture@example.invalid", "账户", stamp, stamp); e != nil {
		t.Fatal(e)
	}
	session := make([]byte, 32)
	for i := range session {
		session[i] = byte(i)
	}
	if _, e = store.DB.ExecContext(ctx, "INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,'2027-01-01')", session, userID, stamp); e != nil {
		t.Fatal(e)
	}
	capture := func() (map[string][]byte, int64, error) {
		files := map[string][]byte{}
		count, e := controllerbackup.SnapshotDatabase(ctx, store.DB, func(name string, emit func(io.Writer) error) error {
			var data bytes.Buffer
			if e := emit(&data); e != nil {
				return e
			}
			files[name] = bytes.Clone(data.Bytes())
			return nil
		})
		return files, count, e
	}
	files, count, e := capture()
	if e != nil || len(files) != 35 || count < 16 {
		t.Fatal("complete source snapshot unavailable", e, len(files), count)
	}
	var schema controllerbackup.DatabaseSchema
	if json.Unmarshal(files["database/schema.json"], &schema) != nil || schema.Schema != 1 || schema.Charset != "utf8mb4" || schema.Collation != "utf8mb4_bin" {
		t.Fatal("database encoding or comparison semantics missing")
	}
	d := json.NewDecoder(bytes.NewReader(files["database/controller_nodes.jsonl"]))
	var header controllerbackup.Table
	if d.Decode(&header) != nil || header.Name != "controller_nodes" || header.Schema != 1 || len(header.Columns) != 10 || header.Collation != "utf8mb4_bin" {
		t.Fatal("typed table header missing")
	}
	for _, want := range []struct {
		id  string
		raw []byte
	}{{"node-a", []byte{0, 255, 0, 10, 34, 92, 128}}, {"node-b", []byte{}}} {
		var row [][]byte
		if d.Decode(&row) != nil || len(row) != 10 {
			t.Fatal("row unavailable")
		}
		values := map[string][]byte{}
		for i, c := range header.Columns {
			values[c.Name] = row[i]
		}
		if string(values["id"]) != want.id || !reflect.DeepEqual(values["capabilities"], want.raw) || values["heartbeat_at"] != nil || string(values["free_cpu"]) != "9223372036854775806" || string(values["updated_at"]) != stamp || string(values["datacenter_id"]) != "香港" {
			t.Fatal("NULL, empty/binary, bigint, Unicode or microsecond precision lost")
		}
	}
	if d.Decode(new(any)) != io.EOF {
		t.Fatal("unexpected source row")
	}
	again, n, e := capture()
	if e != nil || n != count || !reflect.DeepEqual(files, again) {
		t.Fatal("read-only snapshot altered source or is nondeterministic")
	}
	var audit controllerbackup.Table
	if json.NewDecoder(bytes.NewReader(files["database/controller_audit.jsonl"])).Decode(&audit) != nil || audit.NextID == nil || *audit.NextID != "42" {
		t.Fatal("deleted high auto-increment state was lost")
	}
	opRaw := make([]byte, 16)
	if _, e = rand.Read(opRaw); e != nil {
		t.Fatal(e)
	}
	operation := hex.EncodeToString(opRaw)
	targetName := "aster_cloud_restore_" + operation
	if _, e = admin.Exec("CREATE DATABASE `" + targetName + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
		t.Fatal("target fixture creation failed")
	}
	defer func() {
		if _, e := admin.Exec("DROP DATABASE `" + targetName + "`"); e != nil {
			t.Error("owned target cleanup failed")
		}
	}()
	targetConfig := *c
	targetConfig.DBName = targetName
	target, e := control.OpenDSN(targetConfig.FormatDSN())
	if e != nil {
		t.Fatal("target fixture unavailable")
	}
	defer target.DB.Close()
	dir, archive, keyFile := encryptedSQLFixture(t, files, operation)
	restore := func() (controllerbackup.DatabaseRestoreReport, error) {
		var report controllerbackup.DatabaseRestoreReport
		err := controllerbackup.WithVerifiedArchive(archive, keyFile, "source-sql-test", operation, dir, func(a *controllerbackup.Archive) error {
			var err error
			report, err = a.RestoreEmptyDatabase(ctx, target.DB)
			return err
		})
		return report, err
	}
	if _, e = target.DB.ExecContext(ctx, "CREATE TABLE private_marker(id INT PRIMARY KEY,value VARCHAR(30)) ENGINE=InnoDB"); e != nil {
		t.Fatal(e)
	}
	if _, e = target.DB.ExecContext(ctx, "INSERT INTO private_marker VALUES(1,'never overwrite')"); e != nil {
		t.Fatal(e)
	}
	if _, e = restore(); e == nil {
		t.Fatal("populated target was accepted")
	}
	var tables int
	var marker string
	if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 1 || target.DB.QueryRowContext(ctx, "SELECT value FROM private_marker WHERE id=1").Scan(&marker) != nil || marker != "never overwrite" {
		t.Fatal("refusal changed populated target")
	}
	if _, e = target.DB.ExecContext(ctx, "DROP TABLE private_marker"); e != nil {
		t.Fatal(e)
	}
	keyBytes, e := os.ReadFile(keyFile)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(keyFile, []byte("ASTER-CONTROLLER-RECOVERY-1:"+strings.Repeat("72", 32)+"\n"), 0600) != nil {
		t.Fatal("cannot prepare wrong key")
	}
	if _, e = restore(); e == nil {
		t.Fatal("unauthenticated archive reached restore")
	}
	if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 0 {
		t.Fatal("unauthenticated archive created target structure")
	}
	if os.WriteFile(keyFile, keyBytes, 0600) != nil {
		t.Fatal("cannot restore fixture key")
	}
	report, e := restore()
	if e != nil || report.Tables != 34 || report.Rows != count || !report.ExactRowsVerified || !report.DeclaredConstraintsVerified || report.TargetActivationApproved || report.MigrationReady {
		t.Fatal("exact database restore did not pass, or claimed activation", e, report)
	}
	compareTarget := func() {
		t.Helper()
		restored := map[string][]byte{}
		n, e := controllerbackup.SnapshotDatabase(ctx, target.DB, func(name string, emit func(io.Writer) error) error {
			var data bytes.Buffer
			if e := emit(&data); e != nil {
				return e
			}
			restored[name] = bytes.Clone(data.Bytes())
			return nil
		})
		if e != nil || n != count || !reflect.DeepEqual(files, restored) {
			t.Fatal("target differs from the complete authenticated source snapshot", e)
		}
	}
	compareTarget()
	if _, e = restore(); e == nil {
		t.Fatal("completed target was overwritten on replay")
	}
	compareTarget()
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("private restore staging was not cleaned")
	}
	if e = target.Check(ctx); e != nil {
		t.Fatal("restored current schema rejected", e)
	}
	// A foreign table must not be silently omitted or included in the backup.
	if _, e = store.DB.ExecContext(ctx, "CREATE TABLE foreign_table(id INT PRIMARY KEY) ENGINE=InnoDB"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = capture(); e == nil {
		t.Fatal("foreign schema was exported")
	}
}
