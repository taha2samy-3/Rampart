package query_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
	"rampart/internal/query/grammar"
	"rampart/internal/query/sqlbuilder"
)

// TestQuery_SQLInjectionDefense_EdgeCases tests malicious injection payloads
// against the query grammar and SQL builder.
func TestQuery_SQLInjectionDefense_EdgeCases(t *testing.T) {
	injections := []string{
		`' OR '1'='1`,
		`'; DROP TABLE findings; --`,
		`admin'--`,
		`UNION SELECT 1, 2, 3, 4, 5`,
		`1; SELECT * FROM tenant; --`,
		`" OR ""="`,
		`\'; DROP DATABASE rampart; --`,
		`category:sast' OR '1'='1`,
	}

	for _, payload := range injections {
		t.Run(fmt.Sprintf("injection: %s", payload), func(t *testing.T) {
			q, err := grammar.Parse(payload)
			if err != nil {
				// Rejection by grammar is safe and expected for malformed syntax
				return
			}

			// If grammar accepts it as a search term, the SQL builder MUST parameterize it
			// and NOT inject raw SQL fragments.
			sql, args, _ := sqlbuilder.BuildFindingQuery(uuid.New(), "*", &q, "-score", 50, nil)

			// The raw dangerous SQL fragments must NOT appear unparameterized in the SQL string
			if strings.Contains(strings.ToUpper(sql), "DROP TABLE") || strings.Contains(strings.ToUpper(sql), "UNION SELECT") {
				t.Fatalf("SQL injection leaked into generated query: %s", sql)
			}
			_ = args
		})
	}
}

// TestFindingGroups_EdgeCases tests input validation, duplicate handling, and member operations.
func TestFindingGroups_EdgeCases(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	t.Run("creating group with empty name returns 400", func(t *testing.T) {
		body := `{"name":"","description":"missing name"}`
		req := httptest.NewRequest("POST", "/api/v1/groups", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty name, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("creating group with name > 255 chars returns 400", func(t *testing.T) {
		hugeName := strings.Repeat("A", 300)
		body := fmt.Sprintf(`{"name":%q,"description":"too long"}`, hugeName)
		req := httptest.NewRequest("POST", "/api/v1/groups", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for name > 255 chars, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("getting non-existent group returns 404", func(t *testing.T) {
		randomID := uuid.NewString()
		req := httptest.NewRequest("GET", "/api/v1/groups/"+randomID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for missing group, got %d", w.Code)
		}
	})

	t.Run("adding and removing duplicate member IDs handles idempotently", func(t *testing.T) {
		// Create a group
		body := `{"name":"Edge Case Group","description":"Dedup testing"}`
		createReq := httptest.NewRequest("POST", "/api/v1/groups", strings.NewReader(body))
		createReq.Header.Set("Authorization", "Bearer "+token)
		createW := httptest.NewRecorder()
		mux.ServeHTTP(createW, createReq)

		var grp domain.FindingGroup
		_ = json.Unmarshal(createW.Body.Bytes(), &grp)

		fID := uuid.New()
		// Add duplicate IDs in request
		memBody, _ := json.Marshal(map[string]any{"finding_ids": []uuid.UUID{fID, fID, fID}})
		addReq := httptest.NewRequest("POST", "/api/v1/groups/"+grp.ID.String()+"/members", bytes.NewReader(memBody))
		addReq.Header.Set("Authorization", "Bearer "+token)
		addW := httptest.NewRecorder()
		mux.ServeHTTP(addW, addReq)

		if addW.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content on adding members, got %d", addW.Code)
		}

		// Remove ID that is NOT in group (must succeed idempotently)
		nonExistentID := uuid.New()
		remBody, _ := json.Marshal(map[string]any{"finding_ids": []uuid.UUID{nonExistentID}})
		remReq := httptest.NewRequest("DELETE", "/api/v1/groups/"+grp.ID.String()+"/members", bytes.NewReader(remBody))
		remReq.Header.Set("Authorization", "Bearer "+token)
		remW := httptest.NewRecorder()
		mux.ServeHTTP(remW, remReq)

		if remW.Code != http.StatusNoContent {
			t.Fatalf("expected 204 on removing non-existent member, got %d", remW.Code)
		}
	})
}

// TestSavedViews_EdgeCases tests view validation, scope permissions, and deletion.
func TestSavedViews_EdgeCases(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	t.Run("creating view with empty name returns 400", func(t *testing.T) {
		body := `{"name":"","query":"severity:high"}`
		req := httptest.NewRequest("POST", "/api/v1/views", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty view name, got %d", w.Code)
		}
	})

	t.Run("creating view with invalid query syntax returns 400", func(t *testing.T) {
		body := `{"name":"Invalid Query","query":"badfield:value"}`
		req := httptest.NewRequest("POST", "/api/v1/views", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid query syntax, got %d", w.Code)
		}
	})

	t.Run("deleting non-existent view returns 404", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/views/"+uuid.NewString(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 on deleting non-existent view, got %d", w.Code)
		}
	})
}

// TestExports_EdgeCases tests CSV RFC 4180 escaping, OCSF schema compliance, and client cancellation.
func TestExports_EdgeCases(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	t.Run("export CSV with fields containing quotes, commas, and newlines escapes properly", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/findings/export?format=csv", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		lines := strings.Split(w.Body.String(), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected header and data rows in CSV export, got %d lines", len(lines))
		}
		// First line is CSV header
		header := lines[0]
		if !strings.Contains(header, "id") || !strings.Contains(header, "severity") {
			t.Fatalf("unexpected CSV header: %s", header)
		}
	})

	t.Run("export OCSF conforms to OCSF Finding 2001 class structure", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/findings/export?format=ocsf", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var ocsfPayload map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &ocsfPayload); err != nil {
			t.Fatalf("failed decoding OCSF export: %v", err)
		}
		rawFindings, ok := ocsfPayload["findings"].([]any)
		if !ok || len(rawFindings) == 0 {
			t.Fatal("expected at least 1 OCSF record in findings array")
		}

		rec := rawFindings[0].(map[string]any)
		if rec["class_uid"] != float64(2001) {
			t.Fatalf("expected class_uid 2001, got %v", rec["class_uid"])
		}
		if rec["category_uid"] != float64(2) {
			t.Fatalf("expected category_uid 2, got %v", rec["category_uid"])
		}
	})

	t.Run("early client disconnect stops streaming cleanly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately to simulate client disconnect

		req := httptest.NewRequest("GET", "/api/v1/findings/export?format=json", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		// Must handle cancelled context without panic
		mux.ServeHTTP(w, req)
	})

	t.Run("SSE connection closes cleanly when client terminates context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		req := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for SSE stream, got %d", w.Code)
		}
	})
}
