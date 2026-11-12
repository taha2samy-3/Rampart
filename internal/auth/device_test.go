package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"rampart/internal/domain"
)

func TestDeviceAuthorizationFlow(t *testing.T) {
	tokenStore := NewMemoryTokenStore()
	authn := NewAuthenticatorWithStore(tokenStore)
	deviceAuth := NewDeviceAuthManager(tokenStore)

	tenantID := domain.NewID()
	user := &ContextUser{
		Subject:  "developer@example.com",
		Email:    "developer@example.com",
		TenantID: tenantID,
		Role:     RoleMaintainer,
		Scopes:   []string{"ingest", "read", "triage"},
	}

	h := NewHandlers(HandlerDeps{
		Authn:      authn,
		DeviceAuth: deviceAuth,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// 1. Request device code
	codeReq := httptest.NewRequest("POST", "/auth/device/code", stringsReader(`{"client_id":"rampart-cli"}`))
	codeReq.Header.Set("Content-Type", "application/json")
	codeRec := httptest.NewRecorder()
	mux.ServeHTTP(codeRec, codeReq)

	if codeRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /auth/device/code, got %d: %s", codeRec.Code, codeRec.Body.String())
	}

	var codeResp DeviceCodeResponse
	if err := json.Unmarshal(codeRec.Body.Bytes(), &codeResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if codeResp.DeviceCode == "" || codeResp.UserCode == "" {
		t.Fatalf("empty device_code or user_code: %+v", codeResp)
	}

	// 2. Poll token immediately -> must be authorization_pending
	tokenForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {codeResp.DeviceCode},
		"client_id":   {"rampart-cli"},
	}
	pollReq := httptest.NewRequest("POST", "/auth/device/token", stringsReader(tokenForm.Encode()))
	pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pollRec := httptest.NewRecorder()
	mux.ServeHTTP(pollRec, pollReq)

	if pollRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 authorization_pending, got %d: %s", pollRec.Code, pollRec.Body.String())
	}
	var errResp map[string]string
	_ = json.Unmarshal(pollRec.Body.Bytes(), &errResp)
	if errResp["error"] != "authorization_pending" {
		t.Fatalf("expected error=authorization_pending, got %s", errResp["error"])
	}

	// 3. User approves in browser
	verifyBody := map[string]string{"user_code": codeResp.UserCode}
	verifyJSON, _ := json.Marshal(verifyBody)
	verifyReq := httptest.NewRequest("POST", "/auth/device/verify", bytes.NewReader(verifyJSON))
	verifyReq.Header.Set("Content-Type", "application/json")
	// Inject user into context (as session or authenticator would)
	verifyReq = verifyReq.WithContext(ContextWithUser(context.Background(), user))
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /auth/device/verify, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	// 4. Poll token again -> must succeed and return access_token
	pollReq2 := httptest.NewRequest("POST", "/auth/device/token", stringsReader(tokenForm.Encode()))
	pollReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pollRec2 := httptest.NewRecorder()
	mux.ServeHTTP(pollRec2, pollReq2)

	if pollRec2.Code != http.StatusOK {
		t.Fatalf("expected 200 from /auth/device/token, got %d: %s", pollRec2.Code, pollRec2.Body.String())
	}
	var tokenResp DeviceTokenResponse
	if err := json.Unmarshal(pollRec2.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" || tokenResp.TokenType != "Bearer" {
		t.Fatalf("invalid token response: %+v", tokenResp)
	}

	// 5. Authenticate with the issued token
	checkReq := httptest.NewRequest("GET", "/protected", nil)
	checkReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	authenticatedUser, err := authn.AuthenticateRequest(checkReq)
	if err != nil {
		t.Fatalf("failed to authenticate with minted token: %v", err)
	}
	if authenticatedUser.TenantID != tenantID {
		t.Fatalf("expected tenant %s, got %s", tenantID, authenticatedUser.TenantID)
	}
	if authenticatedUser.Role != RoleMaintainer {
		t.Fatalf("expected role %s, got %s", RoleMaintainer, authenticatedUser.Role)
	}
}

func stringsReader(s string) *bytes.Reader {
	return bytes.NewReader([]byte(s))
}
