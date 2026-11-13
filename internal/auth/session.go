package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// ErrCSRF is returned when a state-changing request authenticated by a cookie lacks a valid CSRF token.
var ErrCSRF = errors.New("auth: missing or invalid CSRF token")

// SessionConfig configures browser sessions (doc 14 section 2).
type SessionConfig struct {
	Key      []byte        // 32 bytes: signs CSRF tokens and seals the login state
	Secure   bool          // true when the public URL is https: Secure cookies with the __Host- prefix
	Idle     time.Duration // default 8 h
	Absolute time.Duration // default 24 h
}

// SessionManager creates and validates sessions carried by an opaque, HttpOnly cookie.
type SessionManager struct {
	store IdentityStore
	cfg   SessionConfig
	now   func() time.Time
}

// NewSessionManager validates the configuration and applies the doc 14 defaults.
func NewSessionManager(store IdentityStore, cfg SessionConfig) (*SessionManager, error) {
	if len(cfg.Key) != 32 {
		return nil, fmt.Errorf("auth: session key must be 32 bytes, got %d", len(cfg.Key))
	}
	if cfg.Idle <= 0 {
		cfg.Idle = 8 * time.Hour
	}
	if cfg.Absolute <= 0 {
		cfg.Absolute = 24 * time.Hour
	}
	return &SessionManager{store: store, cfg: cfg, now: time.Now}, nil
}

// SetClock replaces the clock; for tests.
func (m *SessionManager) SetClock(now func() time.Time) { m.now = now }

// CookieName is `__Host-rampart_session` over https (host-bound, Secure, Path=/), plain otherwise (local http).
func (m *SessionManager) CookieName() string { return m.cookie("rampart_session") }

func (m *SessionManager) loginCookieName() string { return m.cookie("rampart_login") }

func (m *SessionManager) cookie(base string) string {
	if m.cfg.Secure {
		return "__Host-" + base
	}
	return base
}

// Create stores a new session and returns the cookie value: <tenant-uuid-hex>.<256-bit secret>.
// The tenant is in the cookie so the lookup can run under that tenant's row-level security.
func (m *SessionManager) Create(ctx context.Context, tenantID, userID uuid.UUID) (string, SessionRecord, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", SessionRecord{}, err
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	now := m.now().UTC()
	rec := SessionRecord{
		ID: domain.NewID(), TenantID: tenantID, UserID: userID, TokenHash: HashToken(raw),
		ExpiresAt: now.Add(m.cfg.Absolute), LastSeenAt: now, CreatedAt: now,
	}
	if err := m.store.CreateSession(ctx, rec); err != nil {
		return "", SessionRecord{}, err
	}
	return hex.EncodeToString(tenantID[:]) + "." + raw, rec, nil
}

func parseSessionCookie(v string) (uuid.UUID, string, error) {
	hexTenant, secret, ok := strings.Cut(v, ".")
	if !ok || len(hexTenant) != 32 || secret == "" {
		return uuid.Nil, "", ErrUnauthorized
	}
	b, err := hex.DecodeString(hexTenant)
	if err != nil {
		return uuid.Nil, "", ErrUnauthorized
	}
	id, err := uuid.FromBytes(b)
	if err != nil || id == domain.NilID {
		return uuid.Nil, "", ErrUnauthorized
	}
	return id, secret, nil
}

// Principal returns the session behind the request cookie. It enforces the absolute and idle
// timeouts, and treats a removed membership or disabled user as a revoked session.
func (m *SessionManager) Principal(r *http.Request) (*SessionPrincipal, error) {
	c, err := r.Cookie(m.CookieName())
	if err != nil || c.Value == "" {
		return nil, ErrUnauthorized
	}
	tenantID, secret, err := parseSessionCookie(c.Value)
	if err != nil {
		return nil, ErrUnauthorized
	}
	p, err := m.store.LookupSession(r.Context(), tenantID, HashToken(secret))
	if err != nil || p == nil {
		return nil, ErrUnauthorized
	}
	now := m.now().UTC()
	s := p.Session
	if now.After(s.ExpiresAt) || now.Sub(s.LastSeenAt) > m.cfg.Idle {
		_ = m.store.DeleteSession(r.Context(), s.TenantID, s.ID)
		return nil, ErrUnauthorized
	}
	if now.Sub(s.LastSeenAt) > time.Minute { // a write per request would be wasteful
		_ = m.store.TouchSession(r.Context(), s.TenantID, s.ID, now)
	}
	return p, nil
}

// Delete ends a session.
func (m *SessionManager) Delete(ctx context.Context, s SessionRecord) error {
	return m.store.DeleteSession(ctx, s.TenantID, s.ID)
}

// CSRFToken is bound to the session: HMAC(key, "csrf" || session id). The SPA reads it from
// GET /auth/session and sends it as X-CSRF-Token on every mutating request.
func (m *SessionManager) CSRFToken(sessionID uuid.UUID) string {
	mac := hmac.New(sha256.New, m.cfg.Key)
	mac.Write([]byte("csrf\x1f"))
	mac.Write(sessionID[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// CheckCSRF reports whether the request carries the CSRF token of the session.
func (m *SessionManager) CheckCSRF(r *http.Request, sessionID uuid.UUID) bool {
	got := r.Header.Get("X-CSRF-Token")
	return got != "" && hmac.Equal([]byte(got), []byte(m.CSRFToken(sessionID)))
}

// SetCookie sets the session cookie: HttpOnly, SameSite=Lax, Path=/ (and Secure over https).
func (m *SessionManager) SetCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: m.CookieName(), Value: value, Path: "/", Expires: expires, HttpOnly: true,
		Secure: m.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie.
func (m *SessionManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: m.CookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: m.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// loginState is what the login redirect remembers until the callback (doc 14 section 2, step 1).
type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Tenant   string    `json:"t"`
	ReturnTo string    `json:"r"`
	Expires  time.Time `json:"e"`
	IdP      string    `json:"idp,omitempty"`
}

func (m *SessionManager) sealer() (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, m.cfg.Key, nil, "rampart/login-state/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (m *SessionManager) setLoginState(w http.ResponseWriter, st loginState) error {
	g, err := m.sealer()
	if err != nil {
		return err
	}
	plain, _ := json.Marshal(st)
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := g.Seal(nonce, nonce, plain, nil)
	http.SetCookie(w, &http.Cookie{
		Name: m.loginCookieName(), Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/",
		MaxAge: 600, HttpOnly: true, Secure: m.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// takeLoginState reads, opens and clears the login-state cookie. It is single use.
func (m *SessionManager) takeLoginState(w http.ResponseWriter, r *http.Request) (loginState, error) {
	var st loginState
	c, err := r.Cookie(m.loginCookieName())
	http.SetCookie(w, &http.Cookie{Name: m.loginCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.cfg.Secure, SameSite: http.SameSiteLaxMode})
	if err != nil {
		return st, ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	g, gerr := m.sealer()
	if err != nil || gerr != nil || len(raw) < g.NonceSize() {
		return st, ErrUnauthorized
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil || json.Unmarshal(plain, &st) != nil || m.now().After(st.Expires) {
		return loginState{}, ErrUnauthorized
	}
	return st, nil
}

// SafeReturnTo accepts only same-origin absolute paths. Anything else becomes "/".
func SafeReturnTo(v string) string {
	if v == "" || v[0] != '/' || strings.HasPrefix(v, "//") || strings.ContainsAny(v, "\\\r\n\t") {
		return "/"
	}
	return v
}
