package control

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func webBuildFixture(t *testing.T) (string, uint32) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(directory, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"index.html": "<!doctype html><title>Reviewed console</title>", "assets/main.js": "const reviewed = true;", "assets/main.css": "body{color:#123}", "assets/icon.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "secret.json": "PRIVATE_CONFIGURATION_SENTINEL", "assets/main.js.map": "PRIVATE_SOURCE_MAP_SENTINEL"} {
		if err = os.WriteFile(filepath.Join(directory, name), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return directory, uint32(os.Geteuid())
}
func webRequest(t *testing.T, handler http.Handler, method, path string, secure bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://console.invalid"+path, nil)
	if secure {
		request.TLS = &tls.ConnectionState{}
	} else {
		request.TLS = nil
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
func TestWebReviewedAssetsRequireHTTPSAndPreserveExactBytes(t *testing.T) {
	directory, owner := webBuildFixture(t)
	handler, err := webOwned(directory, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ path, contentType string }{{"/", "text/html"}, {"/index.html", "text/html"}, {"/assets/main.js", "javascript"}, {"/assets/main.css", "text/css"}, {"/assets/icon.svg", "image/svg+xml"}} {
		t.Run(item.path, func(t *testing.T) {
			response := webRequest(t, handler, "GET", item.path, true)
			if response.Code != 200 {
				t.Fatalf("status %d", response.Code)
			}
			name := strings.TrimPrefix(item.path, "/")
			if name == "" {
				name = "index.html"
			}
			expected, err := os.ReadFile(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			if string(expected) != response.Body.String() {
				t.Fatal("asset bytes changed")
			}
			if !strings.Contains(response.Header().Get("Content-Type"), item.contentType) {
				t.Fatal("wrong content type", response.Header().Get("Content-Type"))
			}
			if response.Header().Get("ETag") != fmt.Sprintf("\"%x\"", sha256.Sum256(expected)) {
				t.Fatal("asset digest binding changed")
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing cache/sniffing boundaries")
			}
			csp := response.Header().Get("Content-Security-Policy")
			for _, directive := range []string{"script-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"} {
				if !strings.Contains(csp, directive) {
					t.Fatal("missing CSP boundary", directive)
				}
			}
			if strings.Contains(csp, "unsafe-eval") {
				t.Fatal("eval allowed")
			}
		})
	}
	if response := webRequest(t, handler, "GET", "/", false); response.Code != 426 || strings.Contains(response.Body.String(), "Reviewed") {
		t.Fatal("plaintext served application bytes")
	}
	if response := webRequest(t, handler, "HEAD", "/assets/main.js", true); response.Code != 200 || response.Body.Len() != 0 || response.Header().Get("ETag") == "" {
		t.Fatal("HEAD is not bodyless")
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if response := webRequest(t, handler, method, "/", true); response.Code != 405 || strings.Contains(response.Body.String(), "Reviewed") {
			t.Fatal("unsafe static method", method, response.Code)
		}
	}
}
func TestWebRejectsTraversalPrivateFilesAndSourceMaps(t *testing.T) {
	directory, owner := webBuildFixture(t)
	handler, err := webOwned(directory, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/secret.json", "/assets/main.js.map", "/.env", "/.git/config", "/../index.html", "/assets/../index.html", "/assets/%2e%2e/index.html", "/assets//main.js", "//index.html", "/assets/.hidden.js", "/assets/main.js/extra", "/assets%5cmain.js"} {
		t.Run(path, func(t *testing.T) {
			response := webRequest(t, handler, "GET", path, true)
			if response.Code != 404 {
				t.Fatalf("unsafe path served %d", response.Code)
			}
			for _, marker := range []string{"PRIVATE_", "Reviewed console", directory, "const reviewed"} {
				if strings.Contains(response.Body.String(), marker) {
					t.Fatal("unsafe response leaked asset or filesystem details")
				}
			}
		})
	}
	if response := webRequest(t, handler, "GET", "/instances/example", true); response.Code != 200 || !strings.Contains(response.Body.String(), "Reviewed console") {
		t.Fatal("valid extensionless SPA path rejected")
	}
}
func TestWebFailsClosedForFilesystemBoundariesAtEveryRead(t *testing.T) {
	t.Run("construction", func(t *testing.T) {
		directory, owner := webBuildFixture(t)
		for _, invalid := range []string{"relative", directory + "/", filepath.Join(directory, "missing")} {
			if _, err := webOwned(invalid, owner); err == nil {
				t.Fatal("invalid root accepted", invalid)
			}
		}
		if _, err := webOwned(directory, owner+1); err == nil {
			t.Fatal("wrong file owner accepted")
		}
		if err := os.Chmod(filepath.Join(directory, "index.html"), 0666); err != nil {
			t.Fatal(err)
		}
		if _, err := webOwned(directory, owner); err == nil {
			t.Fatal("writable entry point accepted")
		}
	})
	for _, kind := range []string{"symlink", "hardlink", "writable_asset", "writable_parent", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			directory, owner := webBuildFixture(t)
			handler, err := webOwned(directory, owner)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "assets/main.js")
			switch kind {
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(filepath.Join(directory, "secret.json"), path)
				}
			case "hardlink":
				if err = os.Remove(path); err == nil {
					err = os.Link(filepath.Join(directory, "secret.json"), path)
				}
			case "writable_asset":
				err = os.Chmod(path, 0666)
			case "writable_parent":
				err = os.Chmod(filepath.Dir(path), 0777)
			case "oversized":
				var file *os.File
				file, err = os.OpenFile(path, os.O_WRONLY, 0644)
				if err == nil {
					err = file.Truncate((5 << 20) + 1)
					if closeErr := file.Close(); err == nil {
						err = closeErr
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			response := webRequest(t, handler, "GET", "/assets/main.js", true)
			if response.Code != 404 || strings.Contains(response.Body.String(), "PRIVATE_") {
				t.Fatal("unsafe asset served", kind, response.Code)
			}
		})
	}
}
