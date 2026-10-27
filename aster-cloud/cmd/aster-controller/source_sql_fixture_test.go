package main

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Compiled CI fixture ONLY, never linked into the installed binary. This uses
// the pinned isolated native MySQL server, not a production/source-host DSN.
// Source host isolation, TLS and material records remain synthetic and the
// native report must explicitly distinguish them from the real SQL snapshot.
func realSourceDatabaseFixture(t *testing.T) map[string][]byte {
	t.Helper()
	c, e := mysql.ParseDSN(os.Getenv("ASTER_MYSQL_TEST_DSN"))
	if e != nil || c.User != "aster_ci" || c.DBName != "aster_ci_test" || c.Net != "unix" || c.Passwd == "" {
		t.Fatal("isolated native SQL fixture required")
	}
	c.MultiStatements = false
	admin, e := sql.Open("mysql", c.FormatDSN())
	if e != nil {
		t.Fatal("fixture unavailable")
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal("fixture entropy unavailable")
	}
	name := "aster_cloud_fixture_" + hex.EncodeToString(nonce)
	if _, e = admin.ExecContext(ctx, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
		t.Fatal("owned source fixture creation failed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE `"+name+"`"); e != nil {
			t.Error("owned source fixture cleanup failed")
		}
	}()
	c.DBName = name
	store, e := control.OpenDSN(c.FormatDSN())
	if e != nil {
		t.Fatal("fixture DSN invalid")
	}
	defer store.DB.Close()
	if e = store.Migrate(ctx); e != nil {
		t.Fatal("fixture schema failed")
	}
	stamp := "2026-10-28 01:02:03.123456"
	for _, row := range []struct {
		id  string
		raw []byte
	}{{"node-a", []byte{0, 255, 0, 10, 34, 92, 128}}, {"node-b", []byte{}}} {
		_, e = store.DB.ExecContext(ctx, "INSERT INTO controller_nodes(id,profile_sha256,datacenter_id,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities,updated_at) VALUES(?,REPEAT('a',64),'香港',0,NULL,9223372036854775806,0,0,?,?)", row.id, row.raw, stamp)
		if e != nil {
			t.Fatal("fixture node values failed")
		}
	}
	for _, statement := range []string{
		"INSERT INTO controller_audit(id,actor,action,target,created_at) VALUES(41,'fixture','fixture','fixture','2026-10-28 01:02:03.123456')",
		"DELETE FROM controller_audit WHERE id=41",
		"INSERT INTO controller_console_users(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at,revision) VALUES(REPEAT('a',32),'restore-fixture@example.invalid','账户','unusable-fixture-hash','admin',1,JSON_ARRAY(),'2026-10-28 01:02:03.123456','2026-10-28 01:02:03.123456',18446744073709551614)",
		"INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(UNHEX(REPEAT('00ff',16)),REPEAT('a',32),'2026-10-28 01:02:03.123456','2027-01-01')",
	} {
		if _, e = store.DB.ExecContext(ctx, statement); e != nil {
			t.Fatal("typed source fixture failed")
		}
	}
	files := map[string][]byte{}
	count, e := controllerbackup.SnapshotDatabase(ctx, store.DB, func(name string, emit func(io.Writer) error) error {
		var data bytes.Buffer
		if e := emit(&data); e != nil {
			return e
		}
		files[name] = bytes.Clone(data.Bytes())
		return nil
	})
	if e != nil || len(files) != 35 || count != 18 {
		t.Fatal("real SQL snapshot inventory failed")
	}
	return files
}
