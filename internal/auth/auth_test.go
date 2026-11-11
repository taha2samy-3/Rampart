package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

func TestAuthenticatorToken(t *testing.T) {
	authn := auth.NewAuthenticator()
	tenantID := domain.NewID()
	token := authn.DefaultAdminToken(tenantID)

	// Valid token test
	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	user, err := authn.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("expected valid authentication, got error: %v", err)
	}
	if user.Role != auth.RoleAdmin {
		t.Errorf("expected RoleAdmin, got %s", user.Role)
	}
	if user.TenantID != tenantID {
		t.Errorf("expected tenant %s, got %s", tenantID, user.TenantID)
	}

	// Invalid token test
	reqInvalid := httptest.NewRequest("GET", "/api/v1/findings", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid-token")

	_, errInvalid := authn.AuthenticateRequest(reqInvalid)
	if errInvalid != auth.ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for bad token, got %v", errInvalid)
	}

	// Expired token test
	expiredToken := "expired_token_123"
	authn.RegisterToken(expiredToken, &auth.TokenRecord{
		Subject:   "test@example.com",
		TenantID:  tenantID,
		Role:      auth.RoleViewer,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
	})

	reqExpired := httptest.NewRequest("GET", "/api/v1/findings", nil)
	reqExpired.Header.Set("X-API-Key", expiredToken)

	_, errExpired := authn.AuthenticateRequest(reqExpired)
	if errExpired != auth.ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for expired token, got %v", errExpired)
	}
}

func TestRequireRoleMiddleware(t *testing.T) {
	authn := auth.NewAuthenticator()
	tenantID := domain.NewID()

	viewerToken := "viewer-token"
	authn.RegisterToken(viewerToken, &auth.TokenRecord{
		Subject:  "viewer@example.com",
		TenantID: tenantID,
		Role:     auth.RoleViewer,
	})

	adminToken := "admin-token"
	authn.RegisterToken(adminToken, &auth.TokenRecord{
		Subject:  "admin@example.com",
		TenantID: tenantID,
		Role:     auth.RoleAdmin,
	})

	handler := authn.Middleware(false)(auth.RequireRole(auth.RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("admin-access-granted"))
	}))

	// 1. Viewer trying admin endpoint -> 403 Forbidden
	reqViewer := httptest.NewRequest("POST", "/admin/action", nil)
	reqViewer.Header.Set("Authorization", "Bearer "+viewerToken)
	recViewer := httptest.NewRecorder()
	handler.ServeHTTP(recViewer, reqViewer)

	if recViewer.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer on admin endpoint, got %d", recViewer.Code)
	}

	// 2. Admin trying admin endpoint -> 200 OK
	reqAdmin := httptest.NewRequest("POST", "/admin/action", nil)
	reqAdmin.Header.Set("Authorization", "Bearer "+adminToken)
	recAdmin := httptest.NewRecorder()
	handler.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin on admin endpoint, got %d", recAdmin.Code)
	}
}
