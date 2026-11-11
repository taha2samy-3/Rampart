package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rampart/internal/ui"
)

func TestUIHandler(t *testing.T) {
	handler := ui.Handler()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html, got %q", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Rampart") || !strings.Contains(body, "queryInput") {
		t.Errorf("expected Rampart Workbench elements in HTML")
	}
}
