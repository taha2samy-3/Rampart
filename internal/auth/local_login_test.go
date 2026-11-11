package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

const adminPassword = "Zq7-correct-horse-9"

type localEnv struct {
	h      http.Handler
	store  *ingest.MemoryStore
	sm     *auth.SessionManager
	now    time.Time
	tenant uuid.UUID
	userID uuid.UUID
}

// newLocalEnv builds the handlers with a local administrator. withOIDC adds an identity provider.
func newLocalEnv(t *testing.T, enabled bool, withOIDC bool) *localEnv {
	t.Helper()
	st := ingest.NewMemoryStore()
	tenant := domain.NewID()
	_ = st.CreateTenant(context.Background(), &domain.Tenant{ID: tenant, Slug: "default", DisplayName: "Default"})
	sm, _ := auth.NewSessionManager(st, auth.SessionConfig{Key: []byte(strings.Repeat("k", 32))})
	e := &localEnv{store: st, sm: sm, now: time.Now(), tenant: tenant}
	sm.SetClock(func() time.Time { return e.now })

	hash, _ := auth.HashPassword(adminPassword)
	e.userID, _ = st.UpsertUser(context.Background(), auth.User{Issuer: auth.LocalIssuer, Subject: "admin", Name: "Local administrator"})
	_ = st.UpsertMember(context.Background(), tenant, e.userID, auth.RoleAdmin)
	_, _ = st.CreateLocalAdmin(context.Background(), auth.LocalAdmin{ID: domain.NewID(), TenantID: tenant, UserID: e.userID, Username: "admin", PasswordHash: hash})

	authn := auth.NewAuthenticatorWithStore(st)
	authn.SetSessions(sm)
	deps := auth.HandlerDeps{Sessions: sm, Identity: st, Tenants: st, Authn: authn, Local: st, Audit: st, LocalLoginEnabled: enabled,
		LocalLimiter: auth.NewRateLimiter(1000, time.Minute)}
	if withOIDC {
		deps.OIDC = auth.NewOIDCClient(auth.OIDCConfig{Issuer: "http://127.0.0.1:1", ClientID: "x"})
	}
	mux := http.NewServeMux()
	auth.NewHandlers(deps).RegisterRoutes(mux)
	e.h = mux
	return e
}

func (e *localEnv) login(body, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/auth/local/login", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = "203.0.113.7:5555"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func creds(user, pw string) string {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	return string(b)
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rampart_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

func actions(e *localEnv) []string {
	var out []string
	for _, a := range e.store.AuditEvents() {
		out = append(out, a.Action)
	}
	return out
}

func TestLocalLoginSucceedsAndIsAudited(t *testing.T) {
	e := newLocalEnv(t, true, false)
	rec := e.login(creds("admin", adminPassword), "application/json")
	c := sessionCookie(rec)
	if rec.Code != http.StatusNoContent || c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("sign-in: %d, cookie %+v", rec.Code, c)
	}
	req := httptest.NewRequest("GET", "/auth/session", nil)
	req.AddCookie(c)
	r2 := httptest.NewRecorder()
	e.h.ServeHTTP(r2, req)
	if r2.Code != 200 || !strings.Contains(r2.Body.String(), `"name":"Local administrator"`) {
		t.Fatalf("session: %d %s", r2.Code, r2.Body.String())
	}
	perm := httptest.NewRequest("GET", "/api/v1/me/permissions", nil)
	perm.AddCookie(c)
	r3 := httptest.NewRecorder()
	e.h.ServeHTTP(r3, perm)
	if !strings.Contains(r3.Body.String(), `"role":"admin"`) {
		t.Errorf("the local administrator is an admin: %s", r3.Body.String())
	}
	ev := e.store.AuditEvents()
	if len(ev) != 1 || ev[0].Action != "local_login_success" || ev[0].Actor != "local:admin" || ev[0].IP != "203.0.113.7" {
		t.Errorf("audit: %+v", ev)
	}
}

// An unknown user and a wrong password must be indistinguishable (same status, same body).
func TestLocalLoginDoesNotRevealWhichUsernamesExist(t *testing.T) {
	e := newLocalEnv(t, true, false)
	wrong := e.login(creds("admin", "definitely-wrong-pw"), "application/json")
	unknown := e.login(creds("nobody", "definitely-wrong-pw"), "application/json")
	if wrong.Code != 401 || unknown.Code != 401 {
		t.Fatalf("both must be 401, got %d and %d", wrong.Code, unknown.Code)
	}
	strip := func(s string) string { // the request id differs per request
		var m map[string]any
		_ = json.Unmarshal([]byte(s), &m)
		delete(m, "request_id")
		b, _ := json.Marshal(m)
		return string(b)
	}
	if strip(wrong.Body.String()) != strip(unknown.Body.String()) {
		t.Errorf("responses differ:\n%s\n%s", wrong.Body.String(), unknown.Body.String())
	}
	if sessionCookie(wrong) != nil || sessionCookie(unknown) != nil {
		t.Error("a failed sign-in must not set a session")
	}
}

func TestLocalLoginLocksAfterFiveWrongPasswordsEvenForTheRightOne(t *testing.T) {
	e := newLocalEnv(t, true, false)
	for i := 1; i <= 5; i++ {
		if rec := e.login(creds("admin", "wrong-password-"+strings.Repeat("x", i)), "application/json"); rec.Code != 401 {
			t.Fatalf("wrong attempt %d: %d", i, rec.Code)
		}
	}
	rec := e.login(creds("admin", adminPassword), "application/json") // the RIGHT password, now locked
	if rec.Code != http.StatusTooManyRequests || sessionCookie(rec) != nil || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a locked account must refuse even the right password: %d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	e.now = e.now.Add(16 * time.Minute) // the lock expires
	if rec := e.login(creds("admin", adminPassword), "application/json"); rec.Code != http.StatusNoContent {
		t.Fatalf("after the lock expires the right password works: %d", rec.Code)
	}
	got := strings.Join(actions(e), ",")
	for _, want := range []string{"local_login_failed", "local_login_locked", "local_login_success"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %s: %s", want, got)
		}
	}
}

func TestLocalLoginFailuresResetOnSuccess(t *testing.T) {
	e := newLocalEnv(t, true, false)
	for round := 0; round < 3; round++ { // 4 wrong, 1 right, repeated: never reaches 5 in a row
		for i := 0; i < 4; i++ {
			e.login(creds("admin", "wrong-password-xx"), "application/json")
		}
		if rec := e.login(creds("admin", adminPassword), "application/json"); rec.Code != http.StatusNoContent {
			t.Fatalf("round %d: success expected, got %d", round, rec.Code)
		}
	}
}

func TestLocalLoginIsRateLimitedPerAddress(t *testing.T) {
	e := newLocalEnv(t, true, false)
	st := e.store
	sm := e.sm
	authn := auth.NewAuthenticatorWithStore(st)
	authn.SetSessions(sm)
	mux := http.NewServeMux()
	auth.NewHandlers(auth.HandlerDeps{Sessions: sm, Identity: st, Tenants: st, Authn: authn, Local: st, Audit: st, LocalLoginEnabled: true,
		LocalLimiter: auth.NewRateLimiter(3, time.Minute)}).RegisterRoutes(mux)
	e.h = mux
	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = e.login(creds("nobody", "x-wrong-password-1"), "application/json")
	}
	if last.Code != http.StatusTooManyRequests || last.Header().Get("Retry-After") == "" {
		t.Fatalf("the address must be throttled: %d", last.Code)
	}
}

func TestLocalLoginIsOffWhenDisabled(t *testing.T) {
	e := newLocalEnv(t, false, true) // an identity provider is configured and keepEnabled is not set
	rec := e.login(creds("admin", adminPassword), "application/json")
	if rec.Code != http.StatusForbidden || sessionCookie(rec) != nil {
		t.Fatalf("a disabled local login must refuse the right password: %d", rec.Code)
	}
	cfg := httptest.NewRecorder()
	e.h.ServeHTTP(cfg, httptest.NewRequest("GET", "/api/v1/ui-config", nil))
	if strings.Contains(cfg.Body.String(), `"password"`) {
		t.Errorf("ui-config must not offer password sign-in when it is off: %s", cfg.Body.String())
	}
}

func TestUIConfigOffersPasswordNextToSSOWhenKeptEnabled(t *testing.T) {
	e := newLocalEnv(t, true, true)
	cfg := httptest.NewRecorder()
	e.h.ServeHTTP(cfg, httptest.NewRequest("GET", "/api/v1/ui-config", nil))
	var c struct {
		Login struct{ Methods []struct{ ID, Type string } }
	}
	_ = json.Unmarshal(cfg.Body.Bytes(), &c)
	if len(c.Login.Methods) != 2 || c.Login.Methods[0].Type != "oidc" || c.Login.Methods[1].Type != "password" {
		t.Fatalf("want oidc then password, got %s", cfg.Body.String())
	}
}

func TestLocalLoginRejectsNonJSONOversizedAndMalformedRequests(t *testing.T) {
	e := newLocalEnv(t, true, false)
	if rec := e.login("username=admin&password="+adminPassword, "application/x-www-form-urlencoded"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form post must be refused (a cross-site form could send it): %d", rec.Code)
	}
	if rec := e.login(creds("admin", strings.Repeat("a", 5000)), "application/json"); rec.Code != http.StatusBadRequest {
		t.Errorf("an oversized password: %d", rec.Code)
	}
	for _, body := range []string{"", "{", `{"username":"admin"}`, `{"password":"x"}`, `[]`} {
		if rec := e.login(body, "application/json"); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", body, rec.Code)
		}
	}
	if rec := e.login(creds("admin", adminPassword), "application/json; charset=utf-8"); rec.Code != http.StatusNoContent {
		t.Errorf("a charset parameter is fine: %d", rec.Code)
	}
}

// Removing the membership disables the account too, even with the right password.
func TestLocalLoginRequiresTenantMembership(t *testing.T) {
	e := newLocalEnv(t, true, false)
	other := domain.NewID()
	_ = e.store.CreateTenant(context.Background(), &domain.Tenant{ID: other, Slug: "other", DisplayName: "Other"})
	hash, _ := auth.HashPassword(adminPassword)
	_, _ = e.store.CreateLocalAdmin(context.Background(), auth.LocalAdmin{ID: domain.NewID(), TenantID: other, UserID: e.userID, Username: "ghost", PasswordHash: hash})
	body, _ := json.Marshal(map[string]string{"tenant": "other", "username": "ghost", "password": adminPassword})
	if rec := e.login(string(body), "application/json"); rec.Code != 401 {
		t.Fatalf("an account whose person is not a member of the tenant must not sign in: %d", rec.Code)
	}
}
