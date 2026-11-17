package query_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/ingest"
	"rampart/internal/query"

	"github.com/google/uuid"
)

// A ticket that gave up is sent back by an administrator only, and only if there is one to send back.
func TestRetryAttestationTicket(t *testing.T) {
	s := &fwStore{MemoryStore: ingest.NewMemoryStore()}
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(s.MemoryStore)
	api := query.NewAPIWithAuth(s, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	maint, rec, _ := auth.GenerateToken(tenantID, auth.RoleMaintainer, "m", []string{"*"}, time.Hour)
	_ = s.SaveToken(context.Background(), rec)
	admin := authn.DefaultAdminToken(tenantID)
	id := uuid.New()
	post := func(token, path string) int {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	path := "/api/v1/attestation-tickets/" + id.String() + "/retry"
	if c := post(maint, path); c != http.StatusForbidden {
		t.Fatalf("a maintainer cannot: %d", c)
	}
	if c := post(admin, path); c != http.StatusConflict || len(s.retried) != 1 {
		t.Fatalf("nothing failed to send back: %d %v", c, s.retried)
	}
	s.canRetry = true
	if c := post(admin, path); c != http.StatusAccepted {
		t.Fatalf("an administrator sends it back: %d", c)
	}
	if c := post(admin, "/api/v1/attestation-tickets/not-an-id/retry"); c != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", c)
	}
}
