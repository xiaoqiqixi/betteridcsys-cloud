package control

import (
	"crypto/sha256"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Web serves only reviewed root-owned build files. It cannot expose config,
// secrets, journals or arbitrary filesystem paths, and never proxies a URL.
func Web(directory string) (http.Handler, error) { return webOwned(directory, 0) }
func webOwned(directory string, owner uint32) (http.Handler, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInput
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInput
	}
	if _, e = readProtected(filepath.Join(directory, "index.html"), false, 5<<20, owner); e != nil {
		return nil, e
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		if r.TLS == nil {
			http.Error(w, "HTTPS required", 426)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if filepath.IsAbs(name) || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, ".") || filepath.Clean(name) != name || strings.Contains(name, "/.") {
			http.NotFound(w, r)
			return
		}
		ext := filepath.Ext(name)
		if ext == "" {
			if strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
			ext = ".html"
		}
		switch ext {
		case ".html", ".js", ".css", ".svg", ".png", ".ico", ".woff2":
		default:
			http.NotFound(w, r)
			return
		}
		raw, e := readProtected(filepath.Join(directory, name), false, 5<<20, owner)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(ext))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", fmt.Sprintf("\"%x\"", sha256.Sum256(raw)))
		if r.Method == "GET" {
			_, _ = w.Write(raw)
		}
	}), nil
}
