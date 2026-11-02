package control

import (
	"bytes"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProvisioningRejectsAmbiguousBindingHeadersAndEmptyQuery(t *testing.T) {
	for _, method := range []string{"POST", "GET"} {
		for _, malformed := range []string{"Idempotency-Key", "X-Aster-Request-SHA256", "empty_query"} {
			t.Run(method+"/"+malformed, func(t *testing.T) {
				request := testRequest(testProfile())
				raw, sha, _ := request.BytesAndDigest()
				store := &fakeStore{}
				path := "/v1/provisioning"
				if method == "GET" {
					path += "/" + request.OperationID
					store.job = Job{OperationID: request.OperationID, ControllerID: "main", RequestSHA: sha, State: "accepted"}
				}
				if malformed == "empty_query" {
					path += "?"
				}
				app := App{Store: store, Config: testConfig(testProfile()), Secrets: Secrets{Billing: strings.Repeat("b", 32)}}
				r := httptest.NewRequest(method, "https://controller.invalid"+path, bytes.NewReader(raw))
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("Authorization", "Bearer "+app.Secrets.Billing)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Idempotency-Key", request.OperationID)
				r.Header.Set("X-Aster-Request-SHA256", sha)
				if malformed != "empty_query" {
					r.Header.Add(malformed, strings.Repeat("f", 64))
				}
				w := httptest.NewRecorder()
				app.Handler().ServeHTTP(w, r)
				want := 400
				if method == "GET" && malformed != "empty_query" {
					want = 409
				}
				if w.Code != want || store.admissions != 0 {
					t.Fatal("ambiguous request reached admission or exposed receipt", w.Code, store.admissions)
				}
			})
		}
	}
}
