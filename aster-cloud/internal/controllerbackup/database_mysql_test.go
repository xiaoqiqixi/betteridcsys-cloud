package controllerbackup_test

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	var dataPlan controllerbackup.DatabasePlan
	if err := controllerbackup.WithVerifiedArchive(archive, keyFile, "source-sql-test", operation, dir, func(a *controllerbackup.Archive) error {
		var err error
		dataPlan, err = a.PlanDatabase(ctx)
		return err
	}); err != nil || dataPlan.Schema != 1 || dataPlan.Charset != "utf8mb4" || dataPlan.Collation != "utf8mb4_bin" || len(dataPlan.Tables) != 34 || dataPlan.Rows != count {
		t.Fatal("authenticated data plan must preserve source encoding and complete row inventory", err, dataPlan)
	}
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
	// The last age tag is checked only after all plaintext. A streaming
	// importer must not create even the target schema before that final tag,
	// nor accept authenticated data followed by undeclared ciphertext.
	originalArchive, e := os.ReadFile(archive)
	if e != nil || len(originalArchive) < 32 {
		t.Fatal("archive fixture unavailable")
	}
	corrupt := bytes.Clone(originalArchive)
	corrupt[len(corrupt)-1] ^= 1
	for _, bad := range [][]byte{originalArchive[:len(originalArchive)-1], corrupt, append(bytes.Clone(originalArchive), 'X')} {
		if os.WriteFile(archive, bad, 0600) != nil {
			t.Fatal("cannot prepare final authentication refusal")
		}
		if _, e = restore(); e != controllerbackup.ErrInvalid {
			t.Fatal("expected explicit refusal before target writes", e)
		}
		if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 0 {
			t.Fatal("late authentication failure reached target DDL")
		}
	}
	if os.WriteFile(archive, originalArchive, 0600) != nil {
		t.Fatal("cannot restore authenticated fixture")
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
	t.Run("foreign-key refusal rolls back all restored rows", func(t *testing.T) {
		badFiles := make(map[string][]byte, len(files))
		for name, raw := range files {
			badFiles[name] = raw
		}
		name := "database/controller_console_sessions.jsonl"
		badFiles[name] = bytes.Replace(files[name], []byte(base64.StdEncoding.EncodeToString([]byte(userID))),
			[]byte(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))), 1)
		if bytes.Equal(files[name], badFiles[name]) {
			t.Fatal("orphan session fixture did not change")
		}
		op := make([]byte, 16)
		if _, e := rand.Read(op); e != nil {
			t.Fatal(e)
		}
		operation := hex.EncodeToString(op)
		database := "aster_cloud_restore_" + operation
		if _, e := admin.ExecContext(ctx, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
			t.Fatal("owned refusal fixture creation failed")
		}
		defer func() {
			if _, e := admin.Exec("DROP DATABASE `" + database + "`"); e != nil {
				t.Error("owned refusal fixture cleanup failed")
			}
		}()
		cfg := *c
		cfg.DBName = database
		target, e := control.OpenDSN(cfg.FormatDSN())
		if e != nil {
			t.Fatal(e)
		}
		defer target.DB.Close()
		dir, archive, key := encryptedSQLFixture(t, badFiles, operation)
		var report controllerbackup.DatabaseRestoreReport
		e = controllerbackup.WithVerifiedArchive(archive, key, "source-sql-test", operation, dir, func(a *controllerbackup.Archive) error {
			var err error
			report, err = a.RestoreEmptyDatabase(ctx, target.DB)
			return err
		})
		if e != controllerbackup.ErrInvalid || report != (controllerbackup.DatabaseRestoreReport{}) {
			t.Fatal("orphan FK was accepted or reported successful", e, report)
		}
		var tables int
		if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 34 {
			t.Fatal("test did not reach the actual migrated SQL target")
		}
		for name := range files {
			if !strings.HasSuffix(name, ".jsonl") {
				continue
			}
			table := strings.TrimSuffix(strings.TrimPrefix(name, "database/"), ".jsonl")
			var count int
			want := 0
			if table == "controller_schema" {
				want = 12
			} else if table == "controller_lock" || table == "controller_identity_lock" {
				want = 1
			}
			if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != want {
				t.Fatal("failed restore retained partial application rows", table)
			}
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 2 {
			t.Fatal("failed restore retained plaintext staging")
		}
	})

	t.Run("explicitly marked empty target retains provisioning evidence", func(t *testing.T) {
		op := make([]byte, 16)
		if _, e := rand.Read(op); e != nil {
			t.Fatal(e)
		}
		operation := hex.EncodeToString(op)
		database := "aster_cloud_restore_" + operation
		if _, e := admin.ExecContext(ctx, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := admin.Exec("DROP DATABASE `" + database + "`"); e != nil {
				t.Error("marked target fixture cleanup failed")
			}
		}()
		cfg := *c
		cfg.DBName = database
		target, e := control.OpenDSN(cfg.FormatDSN())
		if e != nil {
			t.Fatal(e)
		}
		defer target.DB.Close()
		var server string
		if target.DB.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil {
			t.Fatal("fixture UUID unavailable")
		}
		nonce := strings.Repeat("9", 64)
		if _, e = target.DB.ExecContext(ctx, "CREATE TABLE aster_installer_ownership (id INT PRIMARY KEY,nonce CHAR(64) NOT NULL,server_uuid CHAR(36) NOT NULL) ENGINE=InnoDB"); e != nil {
			t.Fatal(e)
		}
		if _, e = target.DB.ExecContext(ctx, "INSERT INTO aster_installer_ownership VALUES(1,?,?)", nonce, server); e != nil {
			t.Fatal(e)
		}
		runtime := cfg
		runtime.User = "aster_restore_runtime"
		owner := map[string]any{"schema": 1, "database": database, "runtime_user": runtime.User, "migration_user": cfg.User, "server_uuid": server, "nonce": nonce, "steps": []string{"database-created", "runtime-created", "runtime-granted", "migration-created", "migration-granted"}, "status": "dedicated-database-provisioned"}
		dir, archive, key := encryptedSQLFixture(t, files, operation)
		restore := func(marked bool) (controllerbackup.DatabaseRestoreReport, error) {
			var result controllerbackup.DatabaseRestoreReport
			e := controllerbackup.WithVerifiedArchive(archive, key, "source-sql-test", operation, dir, func(a *controllerbackup.Archive) error {
				var e error
				if marked {
					raw, e := json.Marshal(owner)
					if e != nil {
						return e
					}
					result, e = a.RestoreMarkedEmptyDatabase(ctx, target.DB, raw, runtime.FormatDSN()+"\n")
					return e
				}
				result, e = a.RestoreEmptyDatabase(ctx, target.DB)
				return e
			})
			return result, e
		}
		unchanged := func() {
			t.Helper()
			var tables int
			var gotNonce, gotServer string
			if target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 1 || target.DB.QueryRowContext(ctx, "SELECT nonce,server_uuid FROM aster_installer_ownership WHERE id=1").Scan(&gotNonce, &gotServer) != nil || gotNonce != nonce || gotServer != server {
				t.Fatal("refused marker check reached DDL or changed ownership")
			}
		}
		if _, e = restore(false); e != controllerbackup.ErrInvalid {
			t.Fatal("ordinary empty-database API silently ignored ownership table", e)
		}
		unchanged()
		for key, bad := range map[string]string{"nonce": strings.Repeat("8", 64), "server_uuid": "00000000-0000-0000-0000-000000000000", "database": "aster_cloud_foreign", "migration_user": "aster_other"} {
			old := owner[key]
			owner[key] = bad
			if _, e = restore(true); e != controllerbackup.ErrInvalid {
				t.Fatal("mismatched target ownership accepted", key, e)
			}
			owner[key] = old
			unchanged()
		}
		// A correctly named table is not a schema exclusion: extra objects and an
		// altered marker definition must both fail before the first business DDL.
		if _, e = target.DB.ExecContext(ctx, "CREATE TABLE foreign_target(id INT PRIMARY KEY)"); e != nil {
			t.Fatal(e)
		}
		if _, e = restore(true); e != controllerbackup.ErrInvalid {
			t.Fatal("foreign target table ignored", e)
		}
		if _, e = target.DB.ExecContext(ctx, "DROP TABLE foreign_target"); e != nil {
			t.Fatal(e)
		}
		unchanged()
		if _, e = target.DB.ExecContext(ctx, "ALTER TABLE aster_installer_ownership ADD COLUMN unapproved INT"); e != nil {
			t.Fatal(e)
		}
		if _, e = restore(true); e != controllerbackup.ErrInvalid {
			t.Fatal("altered marker schema accepted", e)
		}
		if _, e = target.DB.ExecContext(ctx, "ALTER TABLE aster_installer_ownership DROP COLUMN unapproved"); e != nil {
			t.Fatal(e)
		}
		unchanged()
		report, e := restore(true)
		if e != nil || report.Tables != 34 || report.Rows != count || !report.ExactRowsVerified || !report.ProvisioningMarkerPreserved || report.TargetActivationApproved || report.MigrationReady {
			t.Fatal("marked empty target restore not verified", e, report)
		}
		var gotNonce, gotServer string
		var tables int
		if target.DB.QueryRowContext(ctx, "SELECT nonce,server_uuid FROM aster_installer_ownership WHERE id=1").Scan(&gotNonce, &gotServer) != nil || gotNonce != nonce || gotServer != server || target.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()").Scan(&tables) != nil || tables != 35 {
			t.Fatal("restore lost or replaced its own marker")
		}
		var raw []byte
		var datacenter string
		var high string
		if target.DB.QueryRowContext(ctx, "SELECT capabilities,datacenter_id FROM controller_nodes WHERE id='node-a'").Scan(&raw, &datacenter) != nil || !bytes.Equal(raw, []byte{0, 255, 0, 10, 34, 92, 128}) || datacenter != "香港" || target.DB.QueryRowContext(ctx, "SELECT CAST(revision AS CHAR) FROM controller_console_users WHERE id=?", userID).Scan(&high) != nil || high != "18446744073709551614" {
			t.Fatal("marked restore damaged source values")
		}
		if _, e = restore(true); e != controllerbackup.ErrInvalid {
			t.Fatal("marked restore replay overwrote populated target", e)
		}
		if e = target.Check(ctx); e != nil {
			t.Fatal("marked target schema failed", e)
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 2 {
			t.Fatal("marked restore left plaintext")
		}
	})
	// A foreign table must not be silently omitted or included in the backup.
	if _, e = store.DB.ExecContext(ctx, "CREATE TABLE foreign_table(id INT PRIMARY KEY) ENGINE=InnoDB"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = capture(); e == nil {
		t.Fatal("foreign schema was exported")
	}
}
