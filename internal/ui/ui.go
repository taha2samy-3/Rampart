// Package ui serves the embedded single-page application (doc 13 sections 2 and 3).
package ui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"rampart/web"
)

// Options configure the handler.
type Options struct {
	// FS is the build output. Defaults to the embedded web/dist.
	FS fs.FS
	// HSTS adds Strict-Transport-Security; set it only when the public URL is https.
	HSTS bool
}

// ContentSecurityPolicy is the policy doc 13 section 2 requires: nothing from other origins, no
// inline script, no framing.
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

// apiPrefixes belong to the backend: an unknown path under them is a 404, never the SPA shell.
var apiPrefixes = []string{"/api/", "/auth/", "/ingest/", "/hooks/", "/scim/", "/compat/"}

// Handler serves hashed assets as immutable, index.html as no-cache, and falls back to index.html
// for client-side routes so deep links such as /t/acme/findings/<id> work (doc 13 section 3).
func Handler(opts ...Options) http.Handler {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	root := o.FS
	if root == nil {
		sub, err := fs.Sub(web.Dist, "dist")
		if err != nil {
			panic(err) // the dist directory is embedded at compile time
		}
		root = sub
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if o.HSTS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		for _, p := range apiPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				http.NotFound(w, r)
				return
			}
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if info, err := fs.Stat(root, name); err == nil && !info.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				h.Set("Cache-Control", "public, max-age=31536000, immutable")
			} else if name == "index.html" {
				h.Set("Cache-Control", "no-cache")
			}
			http.ServeFileFS(w, r, root, name)
			return
		}
		// A missing file with an extension is a missing asset, not a route.
		if name != "index.html" && path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(root, "index.html"); err != nil {
			http.Error(w, "The web UI is not built. Run `task web:build` and rebuild the binary.", http.StatusServiceUnavailable)
			return
		}
		h.Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, root, "index.html")
	})
}
