package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// The device page (GET /auth/device?user_code=...) reflects an untrusted query parameter into HTML. D63: it must
// never let a crafted user_code or display name break out of the page and run script in a signed-in visitor's
// session (reflected XSS).
func TestDevicePageEscapesUntrustedInput(t *testing.T) {
	h := NewHandlers(HandlerDeps{DeviceAuth: NewDeviceAuthManager(nil)})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	user := &ContextUser{Subject: "a@example.com", Email: `"><script>alert(1)</script>`, TenantID: domain.NewID(), Role: RoleViewer}
	payload := `XXXX-XXXX"><script>alert(document.cookie)</script>`
	req := httptest.NewRequest("GET", "/auth/device?user_code="+url.QueryEscape(payload), nil)
	req = req.WithContext(ContextWithUser(context.Background(), user))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("the page renders an unescaped <script> tag from untrusted input:\n%s", body)
	}
	if !strings.Contains(body, "XXXX-XXXX") {
		t.Fatalf("the safe part of the user code should still render:\n%s", body)
	}
}

// The token the device flow mints reflects the scope the CLI asked for (D63): a narrower request is honoured, an
// empty or unrecognized one falls back to every scope, as every caller got before scope was threaded through.
func TestDeviceFlowHonoursRequestedScope(t *testing.T) {
	cases := []struct {
		requested string
		want      []string
	}{
		{"", allScopes},
		{"bogus", allScopes},
		{"read", []string{"read"}},
		{"read ingest", []string{"read", "ingest"}},
	}
	for _, c := range cases {
		m := NewDeviceAuthManager(NewMemoryTokenStore())
		res, err := m.CreateDeviceCode("rampart-cli", c.requested, "https://rampart.example.com")
		if err != nil {
			t.Fatal(err)
		}
		user := &ContextUser{Email: "dev@example.com", TenantID: domain.NewID(), Role: RoleTriager}
		if err := m.VerifyUserCode(context.Background(), res.UserCode, user); err != nil {
			t.Fatal(err)
		}
		tok, err := m.PollToken(res.DeviceCode, "rampart-cli")
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewAuthenticatorWithStore(m.tokenStore).AuthenticateRequest(authHeaderRequest(tok.AccessToken))
		if err != nil {
			t.Fatal(err)
		}
		if !slicesEqualUnordered(got.Scopes, c.want) {
			t.Fatalf("requested %q: scopes %v, want %v", c.requested, got.Scopes, c.want)
		}
	}
}

func authHeaderRequest(token string) *http.Request {
	r := httptest.NewRequest("GET", "/protected", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func slicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
