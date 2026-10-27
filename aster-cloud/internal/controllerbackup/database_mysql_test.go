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
	if e != nil || len(files) != 34 || count < 16 {
		t.Fatal("complete source snapshot unavailable", e, len(files), count)
	}
	d := json.NewDecoder(bytes.NewReader(files["database/controller_nodes.jsonl"]))
	var header controllerbackup.Table
	if d.Decode(&header) != nil || header.Name != "controller_nodes" || header.Schema != 1 || len(header.Columns) != 10 {
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
	// A foreign table must not be silently omitted or included in the backup.
	if _, e = store.DB.ExecContext(ctx, "CREATE TABLE foreign_table(id INT PRIMARY KEY) ENGINE=InnoDB"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = capture(); e == nil {
		t.Fatal("foreign schema was exported")
	}
}
