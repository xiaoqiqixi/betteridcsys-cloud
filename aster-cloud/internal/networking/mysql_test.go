package networking

import (
	"aster/cloud/internal/identity"
	"aster/cloud/migrations"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func randomID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(b)
}
func fixtureConfig(raw string, fallback bool) (*mysql.Config, error) {
	c, e := mysql.ParseDSN(raw)
	if e != nil || fallback && c.DBName != "aster_ci_test" || !fallback && !strings.Contains(c.DBName, "_test") || c.MultiStatements || c.AllowAllFiles || c.AllowCleartextPasswords || c.AllowOldPasswords || c.TLSConfig == "skip-verify" || c.TLSConfig == "preferred" {
		return nil, ErrInput
	}
	if c.Net == "tcp" {
		host, _, e := net.SplitHostPort(c.Addr)
		ip := net.ParseIP(host)
		if e != nil || ip == nil || !ip.IsLoopback() {
			return nil, ErrInput
		}
	} else if c.Net != "unix" || !filepath.IsAbs(c.Addr) || filepath.Clean(c.Addr) != c.Addr {
		return nil, ErrInput
	}
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 10 * time.Second
	c.WriteTimeout = 10 * time.Second
	return c, nil
}
func mysqlFixture(t *testing.T) (*Store, string) {
	t.Helper()
	raw := os.Getenv("ASTER_NETWORK_TEST_DSN")
	if raw == "" {
		raw = os.Getenv("ASTER_CLOUD_TEST_DSN")
	}
	fallback := false
	if raw == "" {
		raw = os.Getenv("ASTER_MYSQL_TEST_DSN")
		fallback = true
	}
	if raw == "" {
		t.Skip("networking isolated MySQL DSN unset; real database acceptance not run")
	}
	c, e := fixtureConfig(raw, fallback)
	if e != nil {
		t.Fatal("refuse non-test or non-private networking fixture DSN")
	}
	admin, e := sql.Open("mysql", c.FormatDSN())
	if e != nil {
		t.Fatal("cannot open private networking test server")
	}
	name := "aster_cloud_test_network_" + randomID(t)[:16]
	if _, e = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
		admin.Close()
		t.Fatal("cannot create independent networking fixture")
	}
	t.Cleanup(func() {
		if _, e := admin.Exec("DROP DATABASE `" + name + "`"); e != nil {
			t.Error("cannot drop owned networking fixture")
		}
		admin.Close()
	})
	c.DBName = name
	dsn := c.FormatDSN()
	db, e := sql.Open("mysql", dsn)
	if e != nil {
		t.Fatal("cannot open owned networking fixture")
	}
	db.SetMaxOpenConns(24)
	db.SetMaxIdleConns(8)
	t.Cleanup(func() { db.Close() })
	for _, m := range migrations.All() {
		if m.Version > 5 {
			continue
		}
		for _, q := range strings.Split(m.SQL, ";") {
			if strings.TrimSpace(q) != "" {
				if _, e = db.Exec(q); e != nil {
					t.Fatal("network fixture migration failed", m.Version)
				}
			}
		}
	}
	s := &Store{DB: db}
	if e = s.Check(t.Context()); e != nil {
		t.Fatal("new network schema failed exact inspection", e)
	}
	return s, dsn
}
func insertNode(t *testing.T, s *Store, node string) {
	t.Helper()
	if _, e := s.DB.Exec("INSERT INTO controller_nodes(id,profile_sha256,datacenter_id,capabilities,updated_at) VALUES(?,?,?,?,?)", node, strings.Repeat("a", 64), "dc-test", []byte(`{}`), stamp(testNow())); e != nil {
		t.Fatal(e)
	}
}
func insertInstance(t *testing.T, s *Store, id, owner, node, state string) {
	t.Helper()
	if _, e := s.DB.Exec("INSERT INTO controller_instances(id,owner_ref,node_id,hostname,state,resources,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", id, owner, node, "network-fixture", state, []byte(`{"untouched":"financial resource snapshot"}`), stamp(testNow()), stamp(testNow())); e != nil {
		t.Fatal(e)
	}
}
func mustPool(t *testing.T, s *Store, in CreatePoolInput) IPPool {
	t.Helper()
	p, again, e := s.CreatePool(t.Context(), testActor, randomID(t), in, testNow())
	if e != nil || again {
		t.Fatal("pool create", e)
	}
	return p
}
func tableDigest(t *testing.T, s *Store, tables map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for table, key := range tables {
		rows, e := s.DB.Query("SELECT * FROM " + table + " ORDER BY " + key)
		if e != nil {
			t.Fatal(e)
		}
		cols, _ := rows.Columns()
		values := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for j := range ptr {
			ptr[j] = &values[j]
		}
		h := sha256.New()
		for rows.Next() {
			if e = rows.Scan(ptr...); e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(values)
			h.Write(b)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
		out[table] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}
func TestFixtureDSNGuardRejectsProductionAndRemote(t *testing.T) {
	for _, raw := range []string{"root@tcp(192.0.2.1:3306)/aster_cloud_test", "root@tcp(localhost:3306)/aster_cloud_test", "root@tcp(127.0.0.10.evil:3306)/aster_cloud_test", "root@tcp(127.0.0.1:3306)/production", "root@unix(relative.sock)/aster_cloud_test", "root@tcp(127.0.0.1:3306)/aster_cloud_test?multiStatements=true", "root@tcp(127.0.0.1:3306)/aster_cloud_test?tls=skip-verify"} {
		if _, e := fixtureConfig(raw, false); e == nil {
			t.Fatal("unsafe fixture allowed")
		}
	}
	if _, e := fixtureConfig("root@tcp(127.0.0.1:3306)/aster_ci_test", true); e != nil {
		t.Fatal("CI private fixture rejected")
	}
	if _, e := fixtureConfig("root@unix(/private/tmp/mysql.sock)/aster_cloud_test", false); e != nil {
		t.Fatal("private socket rejected")
	}
}

func TestMySQLNetworkIPAMPersistenceReplayAndBoundaries(t *testing.T) {
	s, dsn := mysqlFixture(t)
	ctx := t.Context()
	insertNode(t, s, "node-a")
	insertNode(t, s, "node-b")
	insertInstance(t, s, testInstance, testOwner, "node-a", "running")
	before := tableDigest(t, s, map[string]string{"controller_instances": "id", "controller_nodes": "id", "controller_jobs": "operation_id", "controller_reservations": "operation_id"})
	t.Run("vpc_planned_replay_and_overlap", func(t *testing.T) {
		in := vpcInput()
		id := randomID(t)
		v, again, e := s.CreateVPC(ctx, testActor, id, in, testNow())
		if e != nil || again || v.State != "planned" {
			t.Fatal(v, again, e)
		}
		got, again, e := s.CreateVPC(ctx, testActor, id, in, testNow().Add(time.Hour))
		if e != nil || !again || !reflect.DeepEqual(got, v) {
			t.Fatal("same key changed persistent VPC", e)
		}
		changed := in
		changed.Name = "已修改"
		if _, _, e = s.CreateVPC(ctx, testActor, id, changed, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("changed body accepted", e)
		}
		if _, _, e = s.CreateVPC(ctx, testOwner, id, in, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("other actor adopted replay", e)
		}
		changed = in
		changed.VLANID++
		changed.OwnerRef = randomID(t)
		if _, _, e = s.CreateVPC(ctx, testActor, randomID(t), changed, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("overlap accepted", e)
		}
		changed = in
		changed.CIDR = "10.20.0.0/24"
		if _, _, e = s.CreateVPC(ctx, testActor, randomID(t), changed, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("same VLAN accepted", e)
		}
		changed.NodeID = "node-b"
		if _, _, e = s.CreateVPC(ctx, testActor, randomID(t), changed, testNow()); e != nil {
			t.Fatal("independent node rejected", e)
		}
		changed.NodeID = "unregistered"
		if _, _, e = s.CreateVPC(ctx, testActor, randomID(t), changed, testNow()); !errors.Is(e, ErrNotFound) {
			t.Fatal("unregistered node accepted", e)
		}
		if _, _, e = s.CreatePool(ctx, testActor, id, poolInput(), testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("key reused across resource kinds", e)
		}
		var n int
		if s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='network.vpc.planned'", id).Scan(&n) != nil || n != 1 {
			t.Fatal("duplicate/non-atomic VPC audit")
		}
	})
	t.Run("pool_semantic_replay_and_numeric_first_lease", func(t *testing.T) {
		in := poolInput()
		id := randomID(t)
		pool, again, e := s.CreatePool(ctx, testActor, id, in, testNow())
		if e != nil || again || pool.Addresses[0] != "192.0.2.2" {
			t.Fatal(pool, e)
		}
		in.Addresses = []string{"192.0.2.2", "192.0.2.10"}
		got, again, e := s.CreatePool(ctx, testActor, id, in, testNow())
		if e != nil || !again || !reflect.DeepEqual(got, pool) {
			t.Fatal("sorted semantic replay changed pool", e)
		}
		changed := in
		changed.Enabled = false
		if _, _, e = s.CreatePool(ctx, testActor, id, changed, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
		key := randomID(t)
		request := ReserveInput{pool.ID, testInstance, testOwner, ""}
		lease, again, e := s.Reserve(ctx, testActor, key, request, testNow())
		if e != nil || again || lease.Address != "192.0.2.2" || lease.State != "reserved" {
			t.Fatal(lease, e)
		}
		againLease, again, e := s.Reserve(ctx, testActor, key, request, testNow().Add(time.Hour))
		if e != nil || !again || !reflect.DeepEqual(againLease, lease) {
			t.Fatal("lease replay changed binding", e)
		}
		request.Address = lease.Address
		if _, _, e = s.Reserve(ctx, testActor, key, request, testNow()); !errors.Is(e, ErrConflict) {
			t.Fatal("changed request accepted", e)
		}
		request.Address = "192.0.3.10"
		if _, _, e = s.Reserve(ctx, testActor, randomID(t), request, testNow()); !errors.Is(e, ErrInput) {
			t.Fatal("out-of-pool address accepted", e)
		}
		request.Address = ""
		second, _, e := s.Reserve(ctx, testActor, randomID(t), request, testNow())
		if e != nil || second.Address != "192.0.2.10" {
			t.Fatal("second address", e)
		}
		if _, _, e = s.Reserve(ctx, testActor, randomID(t), request, testNow()); !errors.Is(e, ErrCapacity) {
			t.Fatal("exhausted pool not rejected", e)
		}
		if _, e = s.GetLease(ctx, key); e != nil {
			t.Fatal(e)
		}
		reopened, e := sql.Open("mysql", dsn)
		if e != nil {
			t.Fatal(e)
		}
		defer reopened.Close()
		restored, e := (&Store{DB: reopened}).GetLease(ctx, key)
		if e != nil || !reflect.DeepEqual(restored, lease) {
			t.Fatal("restart lost lease", e)
		}
		var audits int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='network.lease.reserved'", key).Scan(&audits)
		if audits != 1 {
			t.Fatal("lease replay inserted audit", audits)
		}
	})
	t.Run("strict_owner_node_disabled_and_deleted", func(t *testing.T) {
		in := poolInput()
		in.CIDR = "198.51.100.0/24"
		in.Gateway = "198.51.100.1"
		in.Addresses = []string{"198.51.100.2"}
		pool := mustPool(t, s, in)
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, testInstance, randomID(t), ""}, testNow()); !errors.Is(e, ErrForbidden) {
			t.Fatal("owner mismatch accepted", e)
		}
		other := randomID(t)
		insertInstance(t, s, other, testOwner, "node-b", "running")
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, other, testOwner, ""}, testNow()); !errors.Is(e, ErrForbidden) {
			t.Fatal("node mismatch accepted", e)
		}
		deleted := randomID(t)
		insertInstance(t, s, deleted, testOwner, "node-a", "deleted")
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, deleted, testOwner, ""}, testNow()); !errors.Is(e, ErrState) {
			t.Fatal("deleted instance accepted", e)
		}
		in.Enabled = false
		disabled := mustPool(t, s, in)
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{disabled.ID, testInstance, testOwner, ""}, testNow()); !errors.Is(e, ErrState) {
			t.Fatal("disabled pool accepted", e)
		}
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, randomID(t), testOwner, ""}, testNow()); !errors.Is(e, ErrNotFound) {
			t.Fatal("missing instance accepted", e)
		}
	})
	t.Run("vpc_pool_requires_exact_node_cidr_and_owner", func(t *testing.T) {
		in := vpcInput()
		in.CIDR = "10.30.0.0/24"
		in.VLANID = 55
		v, _, e := s.CreateVPC(ctx, testActor, randomID(t), in, testNow())
		if e != nil {
			t.Fatal(e)
		}
		p := CreatePoolInput{"node-a", v.ID, "私网地址池", v.CIDR, "10.30.0.1", []string{"10.30.0.2"}, true}
		changed := p
		changed.NodeID = "node-b"
		if _, _, e = s.CreatePool(ctx, testActor, randomID(t), changed, testNow()); !errors.Is(e, ErrForbidden) {
			t.Fatal("foreign node VPC pool accepted", e)
		}
		changed = p
		changed.CIDR = "10.30.0.0/25"
		if _, _, e = s.CreatePool(ctx, testActor, randomID(t), changed, testNow()); !errors.Is(e, ErrForbidden) {
			t.Fatal("different CIDR accepted", e)
		}
		pool := mustPool(t, s, p)
		owner := randomID(t)
		instance := randomID(t)
		insertInstance(t, s, instance, owner, "node-a", "running")
		if _, _, e = s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, instance, owner, ""}, testNow()); !errors.Is(e, ErrForbidden) {
			t.Fatal("foreign owner used VPC", e)
		}
		if _, _, e = s.Reserve(ctx, testActor, randomID(t), ReserveInput{pool.ID, testInstance, testOwner, ""}, testNow()); e != nil {
			t.Fatal("valid private reservation refused", e)
		}
	})
	t.Run("node_wide_uniqueness_across_overlapping_classic_pools", func(t *testing.T) {
		p := CreatePoolInput{"node-a", "", "共享物理地址", "203.0.113.0/24", "203.0.113.1", []string{"203.0.113.2"}, true}
		one := mustPool(t, s, p)
		two := mustPool(t, s, p)
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{one.ID, testInstance, testOwner, ""}, testNow()); e != nil {
			t.Fatal(e)
		}
		if _, _, e := s.Reserve(ctx, testActor, randomID(t), ReserveInput{two.ID, testInstance, testOwner, ""}, testNow()); !errors.Is(e, ErrCapacity) {
			t.Fatal("same physical address double-allocated", e)
		}
	})
	// No IPAM write alters VM resources, finance jobs, capacity or node config.
	after := tableDigest(t, s, map[string]string{"controller_jobs": "operation_id", "controller_reservations": "operation_id"})
	if after["controller_jobs"] != before["controller_jobs"] || after["controller_reservations"] != before["controller_reservations"] {
		t.Fatal("IPAM changed provisioning/capacity")
	}
	var resources []byte
	if s.DB.QueryRow("SELECT resources FROM controller_instances WHERE id=?", testInstance).Scan(&resources) != nil || string(resources) != `{"untouched":"financial resource snapshot"}` {
		t.Fatal("IPAM rewrote instance resource snapshot")
	}
}

func TestMySQLNetworkConcurrentLastAddressAndReadOnlyPages(t *testing.T) {
	s, _ := mysqlFixture(t)
	insertNode(t, s, "node-a")
	ctx := t.Context()
	in := poolInput()
	in.Addresses = []string{"192.0.2.2"}
	pool := mustPool(t, s, in)
	ids := make([]string, 16)
	for j := range ids {
		ids[j] = randomID(t)
		insertInstance(t, s, ids[j], testOwner, "node-a", "running")
	}
	var success, capacity, other atomic.Int32
	var wg sync.WaitGroup
	for _, instance := range ids {
		key := randomID(t)
		wg.Add(1)
		go func(instance, key string) {
			defer wg.Done()
			_, _, e := s.Reserve(ctx, testActor, key, ReserveInput{pool.ID, instance, testOwner, ""}, testNow())
			if e == nil {
				success.Add(1)
			} else if errors.Is(e, ErrCapacity) {
				capacity.Add(1)
			} else {
				other.Add(1)
			}
		}(instance, key)
	}
	wg.Wait()
	if success.Load() != 1 || capacity.Load() != 15 || other.Load() != 0 {
		t.Fatal("last IP oversold or wrong failure", success.Load(), capacity.Load(), other.Load())
	}
	// 102 extra pools prove fixed 100 ID-keyset pagination; complete address arrays
	// are retained, with a separate serialized-byte budget for large pools.
	for j := range 102 {
		p := in
		p.Name = fmt.Sprintf("池 %03d", j)
		mustPool(t, s, p)
	}
	tables := map[string]string{"controller_network_vpcs": "id", "controller_network_pools": "id", "controller_network_leases": "id", "controller_instances": "id", "controller_nodes": "id", "controller_jobs": "operation_id", "controller_operations": "id", "controller_reservations": "operation_id", "controller_audit": "id"}
	before := tableDigest(t, s, tables)
	page, e := s.ListPools(ctx, "")
	if e != nil || len(page.Items) != 100 || page.NextCursor == nil {
		t.Fatal("first fixed page", e, len(page.Items))
	}
	second, e := s.ListPools(ctx, *page.NextCursor)
	if e != nil || len(second.Items) != 3 || second.NextCursor != nil {
		t.Fatal("second fixed page", e, len(second.Items))
	}
	seen := map[string]bool{}
	for _, p := range append(page.Items, second.Items...) {
		if seen[p.ID] {
			t.Fatal("duplicate page item")
		}
		seen[p.ID] = true
	}
	if _, e = s.ListVPCs(ctx, ""); e != nil {
		t.Fatal(e)
	}
	leases, e := s.ListLeases(ctx, "")
	if e != nil || len(leases.Items) != 1 {
		t.Fatal("lease list", e)
	}
	if _, e = s.GetPool(ctx, pool.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetLease(ctx, leases.Items[0].ID); e != nil {
		t.Fatal(e)
	}
	if after := tableDigest(t, s, tables); !reflect.DeepEqual(before, after) {
		t.Fatal("GET/list changed network/resource/audit state")
	}
	large := in
	large.CIDR = "192.168.0.0/16"
	large.Gateway = "192.168.0.1"
	large.Addresses = ipSequence(t, "192.168.200.1", 4096)
	for range 9 {
		mustPool(t, s, large)
	}
	cursor := ""
	total := 0
	seen = map[string]bool{}
	for n := 0; n < 10; n++ {
		p, e := s.ListPools(ctx, cursor)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(p)
		if len(raw) > PoolPageBudget || len(p.Items) > 100 {
			t.Fatal("pool page over byte/count budget", len(raw), len(p.Items))
		}
		for _, item := range p.Items {
			if seen[item.ID] {
				t.Fatal("budget cursor repeated an item")
			}
			seen[item.ID] = true
			total++
		}
		if p.NextCursor == nil {
			break
		}
		if len(p.Items) == 0 || *p.NextCursor != p.Items[len(p.Items)-1].ID {
			t.Fatal("budget cursor skipped items")
		}
		cursor = *p.NextCursor
	}
	if total != 112 {
		t.Fatal("pool byte-budget pagination lost items", total)
	}
}

func TestMySQLNetworkMigrationPreflightRejectsConflictingShape(t *testing.T) {
	s, _ := mysqlFixture(t)
	ctx := t.Context()
	if _, e := s.DB.Exec("DROP INDEX controller_network_lease_node_address ON controller_network_leases"); e != nil {
		t.Fatal(e)
	}
	if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
		t.Fatal("missing uniqueness index accepted", e)
	}
	if _, e := s.DB.Exec("CREATE INDEX controller_network_lease_node_address ON controller_network_leases(node_id,address)"); e != nil {
		t.Fatal(e)
	}
	if e := CheckMigration(ctx, s.DB, true); !errors.Is(e, ErrConflict) {
		t.Fatal("same-name non-unique index accepted", e)
	}
	if _, e := s.DB.Exec("DROP INDEX controller_network_lease_node_address ON controller_network_leases"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("CREATE UNIQUE INDEX controller_network_lease_node_address ON controller_network_leases(node_id,address)"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("ALTER TABLE controller_network_vpcs MODIFY vlan_id INT UNSIGNED NOT NULL"); e != nil {
		t.Fatal(e)
	}
	if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
		t.Fatal("changed numeric signedness accepted", e)
	}
	if _, e := s.DB.Exec("ALTER TABLE controller_network_vpcs MODIFY vlan_id INT NOT NULL"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("ALTER TABLE controller_network_vpcs ADD unexpected_column INT NULL"); e != nil {
		t.Fatal(e)
	}
	if e := CheckMigration(ctx, s.DB, true); !errors.Is(e, ErrConflict) {
		t.Fatal("unexpected column accepted", e)
	}
	if _, e := s.DB.Exec("ALTER TABLE controller_network_vpcs DROP COLUMN unexpected_column"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP TABLE controller_network_pools"); e != nil {
		t.Fatal(e)
	}
	if e := CheckMigration(ctx, s.DB, true); e != nil {
		t.Fatal("missing partial migration cannot re-enter", e)
	}
	if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
		t.Fatal("recorded schema accepted missing table", e)
	}
	for _, m := range migrations.All() {
		if m.Version != 5 {
			continue
		}
		for _, q := range strings.Split(m.SQL, ";") {
			if strings.TrimSpace(q) != "" {
				if _, e := s.DB.Exec(q); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	if e := s.Check(ctx); e != nil {
		t.Fatal("valid partial migration did not recover", e)
	}
}

const networkPassword = "synthetic network integration password 123"

type httpBrowser struct {
	client       *http.Client
	origin, csrf string
	user         identity.User
}

func browser(t *testing.T, server *httptest.Server) *httpBrowser {
	t.Helper()
	jar, e := cookiejar.New(nil)
	if e != nil {
		t.Fatal(e)
	}
	c := *server.Client()
	c.Jar = jar
	c.Timeout = 15 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &httpBrowser{client: &c, origin: server.URL}
}
func (b *httpBrowser) request(t *testing.T, method, path, body, key string) (int, []byte) {
	t.Helper()
	req, e := http.NewRequest(method, b.origin+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		req.Header.Set("Origin", b.origin)
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, e := b.client.Do(req)
	if e != nil {
		t.Fatal("network fixture HTTPS request failed")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil || res.TLS == nil || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("HTTP/TLS/noncacheable response contract")
	}
	return res.StatusCode, raw
}
func (b *httpBrowser) login(t *testing.T, email string) {
	t.Helper()
	status, raw := b.request(t, "GET", "/console/v1/auth/csrf", "", "")
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	if status != 200 || json.Unmarshal(raw, &csrf) != nil {
		t.Fatal("login challenge", status)
	}
	b.csrf = csrf.Token
	body, _ := json.Marshal(map[string]string{"email": email, "password": networkPassword})
	status, raw = b.request(t, "POST", "/console/v1/auth/login", string(body), "")
	var response struct {
		User identity.User `json:"user"`
		CSRF string        `json:"csrf_token"`
	}
	if status != 200 || json.Unmarshal(raw, &response) != nil || !response.User.Enabled || response.CSRF == "" {
		t.Fatal("login", status)
	}
	b.user, b.csrf = response.User, response.CSRF
}
func (b *httpBrowser) createUser(t *testing.T, email, role string, grants []string) {
	t.Helper()
	in := map[string]any{"email": email, "name": "网络测试用户", "role": role, "password": networkPassword, "reason": "隔离网络权限回归准备"}
	if grants != nil {
		in["permissions"] = grants
	}
	raw, _ := json.Marshal(in)
	status, _ := b.request(t, "POST", "/console/v1/users", string(raw), randomID(t))
	if status != 201 {
		t.Fatal("create fixture user", status)
	}
}
func TestMySQLNetworkHTTPRealSessionsPermissionsAndOriginalIDLookup(t *testing.T) {
	s, _ := mysqlFixture(t)
	// The independent networking Store deliberately tests its schema5 surface.
	// Its real identity HTTP fixture must nevertheless load the CURRENT identity
	// schema and send the same required reason/key as every production client.
	// Do not weaken identity revision reads to accommodate an old test database.
	for _, m := range migrations.All() {
		if m.Version != 11 && m.Version != 12 {
			continue
		}
		for _, q := range strings.Split(m.SQL, ";") {
			if strings.TrimSpace(q) != "" {
				if _, e := s.DB.Exec(q); e != nil {
					t.Fatal("current network identity fixture migration failed", m.Version)
				}
			}
		}
	}
	if e := identity.CheckOperationsSchema(t.Context(), s.DB); e != nil {
		t.Fatal("network identity fixture current schema unavailable", e)
	}
	insertNode(t, s, "node-a")
	insertNode(t, s, "node-b")
	insertInstance(t, s, testInstance, testOwner, "node-a", "running")
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	auth, e := identity.New(s.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = auth.Bootstrap(t.Context(), "network-admin@example.invalid", "网络管理员", []byte(networkPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/console/v1/networks/", auth.Require("", NewHandler(s, []string{"node-a"})))
	mux.Handle("/", auth.Handler())
	admin := browser(t, server)
	admin.login(t, "network-admin@example.invalid")
	admin.createUser(t, "network-viewer@example.invalid", "viewer", nil)
	admin.createUser(t, "network-manager@example.invalid", "custom", []string{"nodes.manage"})
	viewer := browser(t, server)
	viewer.login(t, "network-viewer@example.invalid")
	manager := browser(t, server)
	manager.login(t, "network-manager@example.invalid")
	in := vpcInput()
	raw, _ := json.Marshal(in)
	key := randomID(t)
	status, body := admin.request(t, "POST", APIBase+"vpcs", string(raw), key)
	var saved struct {
		VPC    VPC  `json:"vpc"`
		Replay bool `json:"replay"`
	}
	if status != 201 || json.Unmarshal(body, &saved) != nil || saved.VPC.ID != key || saved.VPC.State != "planned" || saved.Replay {
		t.Fatal("VPC HTTP create", status)
	}
	// Query the original key after a simulated client-side lost ACK: only GET,
	// with no replacement idempotency key or node/data-plane mutation.
	status, body = admin.request(t, "GET", APIBase+"vpcs/"+key, "", "")
	if status != 200 || json.Unmarshal(body, &saved) != nil || saved.VPC.ID != key {
		t.Fatal("original-ID lookup", status)
	}
	status, body = admin.request(t, "POST", APIBase+"vpcs", string(raw), key)
	if status != 200 || json.Unmarshal(body, &saved) != nil || !saved.Replay {
		t.Fatal("canonical replay", status)
	}
	changed := in
	changed.Name = "其他名称"
	changedRaw, _ := json.Marshal(changed)
	if status, _ = admin.request(t, "POST", APIBase+"vpcs", string(changedRaw), key); status != 409 {
		t.Fatal("changed intent accepted", status)
	}
	for _, tc := range []struct {
		b                       *httpBrowser
		method, path, body, key string
		want                    int
	}{{viewer, "GET", APIBase + "vpcs", "", "", 200}, {viewer, "POST", APIBase + "vpcs", string(raw), randomID(t), 403}, {manager, "GET", APIBase + "vpcs", "", "", 403}, {admin, "GET", APIBase + "vpcs?cursor=bad", "", "", 400}, {admin, "GET", APIBase + "vpcs/" + key + "?cursor=" + key, "", "", 400}, {admin, "DELETE", APIBase + "vpcs/" + key, "", "", 405}, {admin, "POST", APIBase + "vpcs", string(raw), "bad", 400}, {admin, "POST", APIBase + "vpcs", strings.TrimSuffix(string(raw), "}") + `,"command":"do-not-execute"}`, randomID(t), 400}} {
		status, _ = tc.b.request(t, tc.method, tc.path, tc.body, tc.key)
		if status != tc.want {
			t.Fatal("authorization/shape", tc.method, tc.path, status, tc.want)
		}
	}
	changed = in
	changed.NodeID = "node-b"
	changedRaw, _ = json.Marshal(changed)
	if status, _ = admin.request(t, "POST", APIBase+"vpcs", string(changedRaw), randomID(t)); status != 403 {
		t.Fatal("unapproved node admitted", status)
	}
	// nodes.manage is independently sufficient for the mutation handler; it is
	// not accidentally widened to nodes.read or inferred from a role name.
	changed = in
	changed.CIDR = "10.40.0.0/24"
	changed.VLANID = 80
	changedRaw, _ = json.Marshal(changed)
	if status, _ = manager.request(t, "POST", APIBase+"vpcs", string(changedRaw), randomID(t)); status != 201 {
		t.Fatal("explicit manager grant rejected", status)
	}
	pool := poolInput()
	poolRaw, _ := json.Marshal(pool)
	poolKey := randomID(t)
	status, body = admin.request(t, "POST", APIBase+"pools", string(poolRaw), poolKey)
	if status != 201 {
		t.Fatal("pool HTTP create", status)
	}
	if status, _ = viewer.request(t, "GET", APIBase+"pools/"+poolKey, "", ""); status != 200 {
		t.Fatal("pool original ID lookup", status)
	}
	lease := ReserveInput{poolKey, testInstance, testOwner, ""}
	leaseRaw, _ := json.Marshal(lease)
	leaseKey := randomID(t)
	status, body = admin.request(t, "POST", APIBase+"leases", string(leaseRaw), leaseKey)
	if status != 201 {
		t.Fatal("reserve HTTP", status)
	}
	if status, _ = viewer.request(t, "GET", APIBase+"leases/"+leaseKey, "", ""); status != 200 {
		t.Fatal("lease original ID lookup", status)
	}
	for _, marker := range []string{`request_sha256`, `actor_id`, networkPassword, admin.csrf, "command", "dsn", "/var/"} {
		if strings.Contains(string(body), marker) {
			t.Fatal("private metadata leaked", marker)
		}
	}
	before := tableDigest(t, s, map[string]string{"controller_network_vpcs": "id", "controller_network_pools": "id", "controller_network_leases": "id", "controller_instances": "id", "controller_audit": "id"})
	for _, path := range []string{"vpcs", "pools", "leases", "vpcs/" + key, "pools/" + poolKey, "leases/" + leaseKey} {
		if status, _ = viewer.request(t, "GET", APIBase+path, "", ""); status != 200 {
			t.Fatal("read-only endpoint failed", status)
		}
	}
	if after := tableDigest(t, s, map[string]string{"controller_network_vpcs": "id", "controller_network_pools": "id", "controller_network_leases": "id", "controller_instances": "id", "controller_audit": "id"}); !reflect.DeepEqual(before, after) {
		t.Fatal("real session GET changed network/resource/audit state")
	}
	old := admin.csrf
	admin.csrf = ""
	status, _ = admin.request(t, "POST", APIBase+"pools", string(poolRaw), randomID(t))
	admin.csrf = old
	if status != 403 {
		t.Fatal("missing CSRF admitted", status)
	}
	if _, e = s.DB.Exec("UPDATE controller_console_users SET enabled=FALSE WHERE id=?", viewer.user.ID); e != nil {
		t.Fatal(e)
	}
	if status, _ = viewer.request(t, "GET", APIBase+"leases", "", ""); status != 401 {
		t.Fatal("revoked session still reads", status)
	}
}
