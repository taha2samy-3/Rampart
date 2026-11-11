package auth_test

import (
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

func TestSafeReturnTo(t *testing.T) {
	ok := map[string]string{"/": "/", "/t/acme/findings?q=a%3Ab": "/t/acme/findings?q=a%3Ab"}
	for in, want := range ok {
		if got := auth.SafeReturnTo(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "//evil.com", "https://evil.com", "evil.com/x", "/\\evil.com", "/a\r\nSet-Cookie: x=1", "javascript:alert(1)"} {
		if got := auth.SafeReturnTo(bad); got != "/" {
			t.Errorf("%q must become /, got %q", bad, got)
		}
	}
}

func TestRolePolicy(t *testing.T) {
	p := auth.RolePolicy{DefaultRole: auth.RoleViewer, Bindings: []auth.Binding{
		{Kind: "user", Name: "boss@example.com", Role: auth.RoleAdmin},
		{Kind: "group", Name: "sec", Role: auth.RoleTriager},
		{Kind: "group", Name: "ops", Role: auth.RoleViewer},
	}}
	cases := []struct {
		email    string
		groups   []string
		existing auth.Role
		want     auth.Role
	}{
		{"boss@example.com", nil, "", auth.RoleAdmin},
		{"x@example.com", []string{"sec", "ops"}, "", auth.RoleTriager},      // strongest binding wins
		{"x@example.com", nil, auth.RoleAdmin, auth.RoleAdmin},               // an existing role is kept when nothing binds
		{"x@example.com", nil, "", auth.RoleViewer},                          // default on first login
		{"x@example.com", []string{"sec"}, auth.RoleAdmin, auth.RoleTriager}, // bindings are the source of truth when they match
	}
	for _, c := range cases {
		if got := p.Resolve(c.email, "sub", c.groups, c.existing); got != c.want {
			t.Errorf("%+v: got %q want %q", c, got, c.want)
		}
	}
	if got := (auth.RolePolicy{}).Resolve("a", "b", nil, ""); got != "" {
		t.Errorf("no default and no binding must mean no access, got %q", got)
	}
}

func TestSessionCookieCannotBeForgedOrMovedAcrossTenants(t *testing.T) {
	st := ingest.NewMemoryStore()
	sm, _ := auth.NewSessionManager(st, auth.SessionConfig{Key: []byte(strings.Repeat("k", 32))})
	a, b := domain.NewID(), domain.NewID()
	uid, _ := st.UpsertUser(nil, auth.User{Issuer: "i", Subject: "s", Email: "e@x"})
	_ = st.UpsertMember(nil, a, uid, auth.RoleViewer)
	value, _, err := sm.Create(nil, a, uid)
	if err != nil {
		t.Fatal(err)
	}
	req := func(v string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: sm.CookieName(), Value: v})
		return r
	}
	if _, err := sm.Principal(req(value)); err != nil {
		t.Fatalf("own cookie: %v", err)
	}
	secret := value[strings.Index(value, ".")+1:]
	moved := strings.Replace(value, value[:32], strings.ReplaceAll(b.String(), "-", ""), 1) // same secret, other tenant
	for name, v := range map[string]string{"another tenant": moved, "garbage": "x", "no secret": value[:32] + ".", "bad hex": strings.Repeat("z", 32) + "." + secret, "empty": ""} {
		if _, err := sm.Principal(req(v)); err == nil {
			t.Errorf("%s must not authenticate", name)
		}
	}
	if len(uuid.UUIDs{}) != 0 {
		t.Fatal()
	}
}

func TestSecureDeploymentsUseHostPrefixedCookies(t *testing.T) {
	st := ingest.NewMemoryStore()
	key := []byte(strings.Repeat("k", 32))
	plain, _ := auth.NewSessionManager(st, auth.SessionConfig{Key: key})
	secure, _ := auth.NewSessionManager(st, auth.SessionConfig{Key: key, Secure: true})
	if plain.CookieName() != "rampart_session" || secure.CookieName() != "__Host-rampart_session" {
		t.Errorf("cookie names: %q %q", plain.CookieName(), secure.CookieName())
	}
	rec := httptest.NewRecorder()
	secure.SetCookie(rec, "v", time.Now().Add(time.Hour))
	c := rec.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
		t.Errorf("a __Host- cookie must be Secure, HttpOnly, Path=/ with no Domain: %+v", c)
	}
	if _, err := auth.NewSessionManager(st, auth.SessionConfig{Key: []byte("short")}); err == nil {
		t.Error("a short key must be refused")
	}
}
