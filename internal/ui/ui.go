package ui

import (
	_ "embed"
	"net/http"
)

//go:embed workbench.html
var workbenchHTML []byte

// Handler serves the embedded Rampart Workbench single-page application (docs/09 line 33, 43, docs/13 §6).
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(workbenchHTML)
	})
}
