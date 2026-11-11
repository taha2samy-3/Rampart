package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS and a token endpoint that really checks PKCE.
type fakeIdP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	challenge string
	nonce     string
	claims    map[string]any
	tokenErr  bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, claims: map[string]any{"sub": "u-1", "email": "alice@example.com", "email_verified": true, "name": "Alice", "groups": []string{"devs"}}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if f.tokenErr || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		std := jwt.Claims{Issuer: f.srv.URL, Audience: jwt.Audience{"rampart"}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}
		raw, _ := jwt.Signed(sig).Claims(std).Claims(f.claims).Claims(map[string]any{"nonce": f.nonce}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
	})
	return f
}

type env struct {
	h      http.Handler
	idp    *fakeIdP
	store  *ingest.MemoryStore
	tenant uuid.UUID
	now    time.Time
	sm     *auth.SessionManager
}

func newEnv(t *testing.T, policy auth.RolePolicy) *env {
	t.Helper()
	idp := newFakeIdP(t)
	st := ingest.NewMemoryStore()
	tenant := domain.NewID()
	_ = st.CreateTenant(nil, &domain.Tenant{ID: tenant, Slug: "default", DisplayName: "Default"})
	sm, err := auth.NewSessionManager(st, auth.SessionConfig{Key: []byte(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{idp: idp, store: st, tenant: tenant, now: time.Now(), sm: sm}
	sm.SetClock(func() time.Time { return e.now })
	authn := auth.NewAuthenticatorWithStore(st)
	authn.SetSessions(sm)
	h := auth.NewHandlers(auth.HandlerDeps{
		OIDC:     auth.NewOIDCClient(auth.OIDCConfig{Issuer: idp.srv.URL, ClientID: "rampart", ClientSecret: "s", RedirectURL: "http://rampart.test/auth/oidc/default/callback", RequireEmailVerified: true}),
		Sessions: sm, Identity: st, Tenants: st, Authn: authn, Policy: policy, Version: "9.9.9",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	e.h = mux
	return e
}

func (e *env) do(method, target string, cookies []*http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// signIn runs login -> IdP -> callback and returns the callback response and the session cookie.
func (e *env) signIn(t *testing.T, returnTo string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	rec := e.do("GET", "/auth/login?tenant=default&return_to="+url.QueryEscape(returnTo), nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), e.idp.srv.URL+"/authorize") || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization request must carry state, nonce and a PKCE S256 challenge: %s", loc)
	}
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	cb := e.do("GET", "/auth/oidc/default/callback?code=abc&state="+url.QueryEscape(q.Get("state")), rec.Result().Cookies(), nil)
	for _, c := range cb.Result().Cookies() {
		if c.Name == "rampart_session" && c.Value != "" {
			return cb, c
		}
	}
	return cb, nil
}

func TestFullLoginFlowCreatesASessionAndCSRFProtectsLogout(t *testing.T) {
	e := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer, Bindings: []auth.Binding{{Kind: "group", Name: "devs", Role: auth.RoleTriager}}})
	cb, sess := e.signIn(t, "/t/default/findings")
	if cb.Code != http.StatusFound || cb.Header().Get("Location") != "/t/default/findings" || sess == nil {
		t.Fatalf("callback: %d -> %q, session=%v", cb.Code, cb.Header().Get("Location"), sess)
	}
	if !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" {
		t.Errorf("session cookie must be HttpOnly, SameSite=Lax, Path=/: %+v", sess)
	}

	rec := e.do("GET", "/auth/session", []*http.Cookie{sess}, nil)
	var body struct {
		User      struct{ Email, Name string }
		Tenant    struct{ Slug string }
		CSRFToken string `json:"csrfToken"`
		ExpiresAt string `json:"expiresAt"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body.User.Email != "alice@example.com" || body.Tenant.Slug != "default" || body.CSRFToken == "" || body.ExpiresAt == "" {
		t.Fatalf("session: %d %s", rec.Code, rec.Body.String())
	}

	perm := e.do("GET", "/api/v1/me/permissions", []*http.Cookie{sess}, nil)
	if !strings.Contains(perm.Body.String(), `"role":"triager"`) { // the group binding outranks the default role
		t.Errorf("permissions: %s", perm.Body.String())
	}

	// a state-changing call needs the CSRF token bound to the session
	if rec := e.do("POST", "/auth/logout", []*http.Cookie{sess}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("logout without CSRF must be 403, got %d", rec.Code)
	}
	if rec := e.do("POST", "/auth/logout", []*http.Cookie{sess}, map[string]string{"X-CSRF-Token": "wrong"}); rec.Code != http.StatusForbidden {
		t.Errorf("logout with a wrong CSRF token must be 403, got %d", rec.Code)
	}
	if rec := e.do("POST", "/auth/logout", []*http.Cookie{sess}, map[string]string{"X-CSRF-Token": body.CSRFToken}); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := e.do("GET", "/auth/session", []*http.Cookie{sess}, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a signed-out session must be 401, got %d", rec.Code)
	}
}

func TestLoginRejectsBadStateReplayAndOpenRedirects(t *testing.T) {
	e := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})

	// open redirect: only same-origin paths survive
	cb, sess := e.signIn(t, "//evil.example.com/x")
	if sess == nil || cb.Header().Get("Location") != "/" {
		t.Errorf("return_to=//evil must become /, got %q", cb.Header().Get("Location"))
	}

	// wrong state
	login := e.do("GET", "/auth/login?tenant=default", nil, nil)
	rec := e.do("GET", "/auth/oidc/default/callback?code=abc&state=forged", login.Result().Cookies(), nil)
	if loc := rec.Header().Get("Location"); loc != "/login?error=invalid_state" {
		t.Errorf("forged state: %q", loc)
	}
	// no login cookie at all (callback opened in another browser)
	if loc := e.do("GET", "/auth/oidc/default/callback?code=abc&state=x", nil, nil).Header().Get("Location"); loc != "/login?error=invalid_state" {
		t.Errorf("no login cookie: %q", loc)
	}

	// the login state is single use: replaying the same callback fails
	login = e.do("GET", "/auth/login?tenant=default", nil, nil)
	loc, _ := url.Parse(login.Header().Get("Location"))
	e.idp.challenge, e.idp.nonce = loc.Query().Get("code_challenge"), loc.Query().Get("nonce")
	target := "/auth/oidc/default/callback?code=abc&state=" + url.QueryEscape(loc.Query().Get("state"))
	if first := e.do("GET", target, login.Result().Cookies(), nil); first.Header().Get("Location") != "/" {
		t.Fatalf("first callback: %q", first.Header().Get("Location"))
	}
	// the browser dropped the cleared cookie; a replay with the old cookie value still must not work
	old := login.Result().Cookies()
	e.idp.tokenErr = true // and the code is not reusable at the IdP either
	if replay := e.do("GET", target, old, nil); strings.HasPrefix(replay.Header().Get("Location"), "/login?error=") == false {
		t.Errorf("a replayed callback must fail, got %q", replay.Header().Get("Location"))
	}
}

func TestIdentityFailuresSendTheBrowserBackWithACode(t *testing.T) {
	cases := []struct {
		name   string
		policy auth.RolePolicy
		claims map[string]any
		want   string
	}{
		{"no role means no access", auth.RolePolicy{}, nil, "no_access"},
		{"unverified email", auth.RolePolicy{DefaultRole: auth.RoleViewer}, map[string]any{"email_verified": false}, "email_unverified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.policy)
			for k, v := range tc.claims {
				e.idp.claims[k] = v
			}
			cb, sess := e.signIn(t, "/")
			if sess != nil || cb.Header().Get("Location") != "/login?error="+tc.want {
				t.Errorf("got %q (session=%v), want /login?error=%s", cb.Header().Get("Location"), sess != nil, tc.want)
			}
		})
	}
	t.Run("unknown tenant", func(t *testing.T) {
		e := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})
		login := e.do("GET", "/auth/login?tenant=nope", nil, nil)
		loc, _ := url.Parse(login.Header().Get("Location"))
		e.idp.challenge, e.idp.nonce = loc.Query().Get("code_challenge"), loc.Query().Get("nonce")
		cb := e.do("GET", "/auth/oidc/default/callback?code=abc&state="+url.QueryEscape(loc.Query().Get("state")), login.Result().Cookies(), nil)
		if cb.Header().Get("Location") != "/login?error=tenant_not_found" {
			t.Errorf("got %q", cb.Header().Get("Location"))
		}
	})
}

func TestSessionTimeoutsAndTenantSwitch(t *testing.T) {
	e := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})
	_, sess := e.signIn(t, "/")
	if sess == nil {
		t.Fatal("no session")
	}
	// idle: 8 h without activity ends the session; activity within it extends it
	e.now = e.now.Add(7 * time.Hour)
	if rec := e.do("GET", "/auth/session", []*http.Cookie{sess}, nil); rec.Code != 200 {
		t.Fatalf("7 h later: %d", rec.Code)
	}
	e.now = e.now.Add(7 * time.Hour) // 14 h since login but only 7 h idle
	if rec := e.do("GET", "/auth/session", []*http.Cookie{sess}, nil); rec.Code != 200 {
		t.Fatalf("activity must extend the idle window: %d", rec.Code)
	}
	e.now = e.now.Add(9 * time.Hour) // idle > 8 h
	if rec := e.do("GET", "/auth/session", []*http.Cookie{sess}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("idle timeout: %d", rec.Code)
	}

	// absolute: 24 h from login regardless of activity
	e2 := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})
	_, s2 := e2.signIn(t, "/")
	for i := 0; i < 5; i++ {
		e2.now = e2.now.Add(6 * time.Hour)
		code := e2.do("GET", "/auth/session", []*http.Cookie{s2}, nil).Code
		if i < 3 && code != 200 || i >= 4 && code != 401 {
			t.Fatalf("step %d (%d h): %d", i, (i+1)*6, code)
		}
	}

	// tenant switch: only into a tenant the person belongs to, and the session id rotates
	e3 := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})
	_, s3 := e3.signIn(t, "/")
	other := domain.NewID()
	_ = e3.store.CreateTenant(nil, &domain.Tenant{ID: other, Slug: "other", DisplayName: "Other"})
	csrf := func(c *http.Cookie) string {
		var b struct {
			CSRFToken string `json:"csrfToken"`
		}
		_ = json.Unmarshal(e3.do("GET", "/auth/session", []*http.Cookie{c}, nil).Body.Bytes(), &b)
		return b.CSRFToken
	}
	post := func(c *http.Cookie, slug string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/auth/tenant", strings.NewReader(`{"tenant":"`+slug+`"}`))
		req.AddCookie(c)
		req.Header.Set("X-CSRF-Token", csrf(c))
		rec := httptest.NewRecorder()
		e3.h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(s3, "other"); rec.Code != http.StatusForbidden {
		t.Fatalf("switching into a tenant without membership must be 403, got %d", rec.Code)
	}
	userID := func() uuid.UUID {
		l, _ := e3.store.ListUserTenants(nil, uuid.Nil)
		_ = l
		var b struct{ User struct{ ID string } }
		_ = json.Unmarshal(e3.do("GET", "/auth/session", []*http.Cookie{s3}, nil).Body.Bytes(), &b)
		return uuid.MustParse(b.User.ID)
	}()
	_ = e3.store.UpsertMember(nil, other, userID, auth.RoleAdmin)
	rec := post(s3, "other")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("switch: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e3.do("GET", "/auth/session", []*http.Cookie{s3}, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the old session id must be dead after a switch, got %d", rec.Code)
	}
	var fresh *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "rampart_session" {
			fresh = c
		}
	}
	if fresh == nil || !strings.Contains(string(e3.do("GET", "/auth/session", []*http.Cookie{fresh}, nil).Body.Bytes()), `"slug":"other"`) {
		t.Fatalf("the new session must be in the other tenant")
	}
}

func TestUIConfigIsPublicAndReportsTheSignInMethod(t *testing.T) {
	e := newEnv(t, auth.RolePolicy{DefaultRole: auth.RoleViewer})
	rec := e.do("GET", "/api/v1/ui-config", nil, nil)
	var c struct {
		Product, Version string
		Login            struct{ Methods []struct{ ID, Type string } }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if rec.Code != 200 || c.Product != "Rampart" || c.Version != "9.9.9" || len(c.Login.Methods) != 1 || c.Login.Methods[0].Type != "oidc" {
		t.Fatalf("ui-config: %d %s", rec.Code, rec.Body.String())
	}
	// no IdP configured: the UI is told there is no way in instead of failing
	bare := auth.NewHandlers(auth.HandlerDeps{Authn: auth.NewAuthenticator()})
	mux := http.NewServeMux()
	bare.RegisterRoutes(mux)
	r2 := httptest.NewRecorder()
	mux.ServeHTTP(r2, httptest.NewRequest("GET", "/api/v1/ui-config", nil))
	if !strings.Contains(r2.Body.String(), `"methods":[]`) {
		t.Errorf("no IdP: %s", r2.Body.String())
	}
	r3 := httptest.NewRecorder()
	mux.ServeHTTP(r3, httptest.NewRequest("GET", "/auth/login", nil))
	if r3.Code != http.StatusServiceUnavailable || r3.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("login without an IdP: %d %s", r3.Code, r3.Header().Get("Content-Type"))
	}
}
