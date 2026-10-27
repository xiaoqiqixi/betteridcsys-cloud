package control

import (
	"aster/billing/controllerapi"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type resourceViewFixture struct {
	fakeStore
	value   Instance
	failure error
	reads   int
}

func (s *resourceViewFixture) Instance(_ context.Context, instance string) (Instance, error) {
	s.reads++
	if s.failure != nil {
		return Instance{}, s.failure
	}
	if instance != s.value.ID {
		return Instance{}, ErrNotFound
	}
	return s.value, nil
}
func resourceViewApp() (App, *resourceViewFixture) {
	p := testProfile()
	store := &resourceViewFixture{value: Instance{ID: strings.Repeat("1", 32), OwnerRef: strings.Repeat("2", 32), NodeID: p.ID, Hostname: "owned-instance", State: "created", Resources: testResources(p), CreatedAt: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 10, 22, 0, 1, 0, 0, time.UTC)}}
	return App{Store: store, Config: testConfig(p), Secrets: Secrets{strings.Repeat("b", 64), strings.Repeat("r", 64), strings.Repeat("w", 64)}}, store
}
func TestResourceViewIsBillingOnlyOwnerScopedAndReadOnly(t *testing.T) {
	app, store := resourceViewApp()
	path := "/v1/resources/" + store.value.ID
	headers := map[string]string{"X-Aster-Owner-Ref": store.value.OwnerRef}
	for _, item := range []struct {
		name, method, token string
		secure              bool
		want                int
	}{{"billing", "GET", app.Secrets.Billing, true, 200}, {"read token not billing", "GET", app.Secrets.AdminRead, true, 403}, {"write token not billing", "GET", app.Secrets.AdminWrite, true, 403}, {"missing token", "GET", "", true, 401}, {"plaintext", "GET", app.Secrets.Billing, false, 426}, {"mutation", "POST", app.Secrets.Billing, true, 405}, {"head is not an observation", "HEAD", app.Secrets.Billing, true, 405}} {
		t.Run(item.name, func(t *testing.T) {
			before := store.reads
			response := requestHTTP(app, item.method, path, item.token, nil, headers, item.secure)
			if response.Code != item.want {
				t.Fatalf("status %d want %d", response.Code, item.want)
			}
			if item.want != 200 && store.reads != before {
				t.Fatal("unauthorized/unsafe request queried resource")
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("resource privacy headers missing")
			}
		})
	}
	if store.admissions != 0 || store.claims != 0 {
		t.Fatal("resource read changed provisioning lifecycle")
	}
	for _, owner := range []string{"", strings.Repeat("3", 32), strings.Repeat("A", 32), "invalid"} {
		before := store.reads
		response := requestHTTP(app, "GET", path, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": owner}, true)
		if response.Code != 404 {
			t.Fatal("owner mismatch reveals resource", owner, response.Code)
		}
		if owner == "" && store.reads != before {
			t.Fatal("missing owner reached store")
		}
		if strings.Contains(response.Body.String(), store.value.Hostname) {
			t.Fatal("foreign owner received resource")
		}
	}
}
func TestResourceViewRejectsAmbiguousOwnerAndBrowserQueryBeforeLookup(t *testing.T) {
	app, store := resourceViewApp()
	path := "/v1/resources/" + store.value.ID
	for _, kind := range []string{"duplicate_owner", "comma_joined_owner", "origin", "query", "invalid_resource", "extra_path"} {
		t.Run(kind, func(t *testing.T) {
			target := path
			if kind == "query" {
				target += "?owner_ref=" + store.value.OwnerRef
			}
			if kind == "invalid_resource" {
				target = "/v1/resources/not-a-valid-instance"
			}
			if kind == "extra_path" {
				target += "/extra"
			}
			request := httptest.NewRequest("GET", "https://controller.invalid"+target, nil)
			request.TLS = &tls.ConnectionState{}
			request.Header.Set("Authorization", "Bearer "+app.Secrets.Billing)
			request.Header.Set("X-Aster-Owner-Ref", store.value.OwnerRef)
			switch kind {
			case "duplicate_owner":
				request.Header.Add("X-Aster-Owner-Ref", store.value.OwnerRef)
			case "comma_joined_owner":
				request.Header.Set("X-Aster-Owner-Ref", store.value.OwnerRef+", "+store.value.OwnerRef)
			case "origin":
				request.Header.Set("Origin", "https://browser.invalid")
			}
			before := store.reads
			response := httptest.NewRecorder()
			app.Handler().ServeHTTP(response, request)
			expected := 404
			if kind == "origin" {
				expected = 403
			}
			if kind == "query" {
				expected = 400
			}
			if response.Code != expected {
				t.Fatalf("status %d want %d", response.Code, expected)
			}
			if before != store.reads {
				t.Fatal("invalid boundary reached resource store")
			}
		})
	}
}
func TestResourceViewExactProjectionDoesNotExpandFinancialResult(t *testing.T) {
	app, store := resourceViewApp()
	response := requestHTTP(app, "GET", "/v1/resources/"+store.value.ID, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": store.value.OwnerRef}, true)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	expected := []string{"protocol", "resource_id", "owner_ref", "hostname", "state", "node_id", "resources", "updated_at"}
	if len(fields) != len(expected) {
		t.Fatal("resource response field contract changed", len(fields))
	}
	for _, key := range expected {
		if _, ok := fields[key]; !ok {
			t.Fatal("missing resource field", key)
		}
	}
	var value ResourceView
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.Protocol != "aster.resource/1" || value.ResourceID != store.value.ID || value.OwnerRef != store.value.OwnerRef || value.State != "created" || !reflect.DeepEqual(value.Resources, store.value.Resources) || !value.UpdatedAt.Equal(store.value.UpdatedAt) {
		t.Fatal("projection invented live state or changed approved resources")
	}
	for _, secret := range []string{"password", "token", "dsn_file", "client_key_file", "request_json", "request_sha256", "manifest_sha256", "fence_token", app.Secrets.Billing, app.Config.TLSKeyFile, app.Config.Nodes[0].Endpoint} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("private material in resource response", secret)
		}
	}
	request := testRequest(testProfile())
	raw, digest, err := request.BytesAndDigest()
	if err != nil {
		t.Fatal(err)
	}
	job := Job{OperationID: request.OperationID, OrderID: request.OrderID, ControllerID: request.Product.ControllerID, RequestSHA: digest, RequestJSON: raw, State: "succeeded", InstanceID: store.value.ID}
	financial := job.Result()
	if !financial.Matches(request) {
		t.Fatal("original financial result binding changed")
	}
	resultJSON, err := json.Marshal(financial)
	if err != nil {
		t.Fatal(err)
	}
	var immutable map[string]json.RawMessage
	if err = json.Unmarshal(resultJSON, &immutable); err != nil {
		t.Fatal(err)
	}
	if len(immutable) != 6 {
		t.Fatal("resource view expanded immutable financial result")
	}
	var result controllerapi.Result
	if err = json.Unmarshal(resultJSON, &result); err != nil || !result.Matches(request) {
		t.Fatal("financial result no longer round trips", err)
	}
}
func TestResourceViewFailureNeverLeaksStoreError(t *testing.T) {
	app, store := resourceViewApp()
	for _, failure := range []error{ErrNotFound, ErrUnavailable, errors.New("PRIVATE_DSN_AND_PASSWORD_SENTINEL")} {
		store.failure = failure
		response := requestHTTP(app, "GET", "/v1/resources/"+store.value.ID, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": store.value.OwnerRef}, true)
		if response.Code != 404 || strings.Contains(response.Body.String(), "PRIVATE_") || strings.Contains(response.Body.String(), store.value.OwnerRef) {
			t.Fatal("resource failure leaked private detail")
		}
	}
	app.Store = &fakeStore{}
	response := requestHTTP(app, "GET", "/v1/resources/"+store.value.ID, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": store.value.OwnerRef}, true)
	if response.Code != 503 {
		t.Fatal("store without observation capability fabricated a response")
	}
}
