package control

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

type crashDispatchRPC struct{ endpoint string }

func (r crashDispatchRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}

func (r crashDispatchRPC) Send(ctx context.Context, raw []byte, _ string) (nodeproto.NodeResult, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(raw))
	response, err := http.DefaultClient.Do(req)
	if response != nil {
		response.Body.Close()
	}
	return nodeproto.NodeResult{}, err
}
func (r crashDispatchRPC) Lookup(context.Context, string, string) (nodeproto.NodeResult, error) {
	return nodeproto.NodeResult{}, ErrUnavailable
}

// This is also the subprocess entry point: the parent kills it while an actual
// POST is blocked, after the MySQL sending commit and before any reply.
func TestMySQLDispatcherKilledDuringPOST(t *testing.T) {
	if os.Getenv("ASTER_DISPATCH_CRASH_CHILD") == "1" {
		s, err := OpenDSN(os.Getenv("ASTER_DISPATCH_CRASH_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.DB.Close()
		var cfg Config
		if json.Unmarshal([]byte(os.Getenv("ASTER_DISPATCH_CRASH_CONFIG")), &cfg) != nil {
			t.Fatal("config")
		}
		d := NewDispatcher(s, cfg)
		factory := func(context.Context, NodeProfile) (NodeRPC, error) {
			return crashDispatchRPC{os.Getenv("ASTER_DISPATCH_CRASH_URL")}, nil
		}
		d.Billing.RPC = factory
		d.Operations.RPC = factory
		if err = d.Step(context.Background(), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		t.Fatal("child must be killed during POST")
	}
	for _, kind := range []string{"billing", "operation"} {
		t.Run(kind, func(t *testing.T) {
			s, dsn := mysqlTestStore(t)
			ctx := context.Background()
			p, now := mysqlNode(t, s)
			cfg := testConfig(p)
			cfg.Dispatcher.Enabled = true
			req := testRequest(p)
			job, _, err := s.Admit(ctx, req, cfg.Candidates(req), now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			op := job.OperationID
			if kind == "operation" {
				if _, err = s.Claim(ctx, op, p.Digest(), now, time.Minute); err != nil {
					t.Fatal(err)
				}
				if _, err = s.Complete(ctx, op, "succeeded", now); err != nil {
					t.Fatal(err)
				}
				value, _, err := s.CreateOperation(ctx, cfg, id(), job.InstanceID, id(), OperationInput{Action: "start"}, now)
				if err != nil {
					t.Fatal(err)
				}
				op = value.ID
			}
			posted := make(chan struct{}, 1)
			release := make(chan struct{})
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				posted <- struct{}{}
				<-release
				w.WriteHeader(503)
			}))
			defer server.Close()
			defer close(release)
			raw, _ := json.Marshal(cfg)
			cmd := exec.Command(os.Args[0], "-test.run=^TestMySQLDispatcherKilledDuringPOST$")
			cmd.Env = append(os.Environ(), "ASTER_DISPATCH_CRASH_CHILD=1", "ASTER_DISPATCH_CRASH_DSN="+dsn, "ASTER_DISPATCH_CRASH_CONFIG="+string(raw), "ASTER_DISPATCH_CRASH_URL="+server.URL)
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			select {
			case <-posted:
			case <-time.After(20 * time.Second):
				t.Fatal("child never reached POST")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			var state string
			query := "SELECT state FROM controller_jobs WHERE operation_id=?"
			if kind == "operation" {
				query = "SELECT state FROM controller_operations WHERE id=?"
			}
			if err = s.DB.QueryRow(query, op).Scan(&state); err != nil || state != "sending" {
				t.Fatal("crash lost sending intent", state, err)
			}
			d := NewDispatcher(s, cfg)
			rpc := &consoleRPC{Drop: true}
			factory := func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }
			d.Billing.RPC = factory
			d.Operations.RPC = factory
			for n := 1; n <= 3; n++ {
				_ = d.Step(ctx, now.Add(time.Duration(n)*2*time.Minute))
			}
			if posts.Load() != 1 || rpc.posts.Load() != 0 {
				t.Fatal("expired lease resent a POST")
			}
			if kind == "billing" {
				_, err = s.Complete(ctx, op, "uncertain", now)
			} else {
				_, err = s.CompleteOperation(ctx, cfg, op, "uncertain", nil, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.LeaseDispatch(ctx, id(), cfg, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
				t.Fatal("uncertain selected", err)
			}
		})
	}
}

func TestDispatcherDisabledByDefault(t *testing.T) {
	d := NewDispatcher(nil, Config{})
	if !errors.Is(d.Step(context.Background(), time.Now()), ErrState) {
		t.Fatal("disabled dispatcher used store")
	}
	d.Run(context.Background())
}

func TestMySQLDispatcherLeaseExpiresOnlyBeforeSend(t *testing.T) {
	s, _ := mysqlTestStore(t)
	p, now := mysqlNode(t, s)
	cfg := testConfig(p)
	ctx := context.Background()
	req := testRequest(p)
	j, _, err := s.Admit(ctx, req, cfg.Candidates(req), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.LeaseDispatch(ctx, id(), cfg, now)
	if err != nil || first.OperationID != j.OperationID {
		t.Fatal(err)
	}
	if _, err = s.LeaseDispatch(ctx, id(), cfg, now.Add(30*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatal("lease stolen", err)
	}
	next, err := s.LeaseDispatch(ctx, id(), cfg, now.Add(time.Minute))
	if err != nil || next.State != "accepted" {
		t.Fatal("pre-send lease cannot recover", err)
	}
}
