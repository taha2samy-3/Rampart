package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func TestDeviceVerify_RequiresCSRF(t *testing.T) {
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	deviceAuth := auth.NewDeviceAuthManager(st)

	tenantID := domain.NewID()
	_ = st.CreateTenant(context.Background(), &domain.Tenant{ID: tenantID, Slug: "default", DisplayName: "Default"})
	sm, err := auth.NewSessionManager(st, auth.SessionConfig{Key: []byte(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatal(err)
	}
	authn.SetSessions(sm)

	userID, err := st.UpsertUser(context.Background(), auth.User{Issuer: "local", Subject: "dev", Email: "dev@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.UpsertMember(context.Background(), tenantID, userID, auth.RoleMaintainer)

	h := auth.NewHandlers(auth.HandlerDeps{
		Authn:      authn,
		DeviceAuth: deviceAuth,
		Sessions:   sm,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// 1. Request device code
	codeReq := httptest.NewRequest("POST", "/auth/device/code", strings.NewReader(`{"client_id":"rampart-cli"}`))
	codeReq.Header.Set("Content-Type", "application/json")
	codeRec := httptest.NewRecorder()
	mux.ServeHTTP(codeRec, codeReq)

	var codeResp auth.DeviceCodeResponse
	_ = json.Unmarshal(codeRec.Body.Bytes(), &codeResp)

	// Create user session cookie
	cookieVal, rec, err := sm.Create(context.Background(), tenantID, userID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Request verify with session cookie but NO CSRF token -> MUST return 403 Forbidden
	noCSRFForm := url.Values{"user_code": {codeResp.UserCode}}
	reqNoCSRF := httptest.NewRequest("POST", "/auth/device/verify", strings.NewReader(noCSRFForm.Encode()))
	reqNoCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNoCSRF.AddCookie(&http.Cookie{Name: sm.CookieName(), Value: cookieVal})
	recNoCSRF := httptest.NewRecorder()
	mux.ServeHTTP(recNoCSRF, reqNoCSRF)

	if recNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when CSRF token is missing, got %d: %s", recNoCSRF.Code, recNoCSRF.Body.String())
	}

	// 3. Request verify with valid CSRF token in form value -> MUST succeed (200 OK)
	validCSRF := sm.CSRFToken(rec.ID)
	validForm := url.Values{"user_code": {codeResp.UserCode}, "csrf_token": {validCSRF}}
	reqValid := httptest.NewRequest("POST", "/auth/device/verify", strings.NewReader(validForm.Encode()))
	reqValid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqValid.AddCookie(&http.Cookie{Name: sm.CookieName(), Value: cookieVal})
	recValid := httptest.NewRecorder()
	mux.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when valid CSRF token is provided, got %d: %s", recValid.Code, recValid.Body.String())
	}
}
