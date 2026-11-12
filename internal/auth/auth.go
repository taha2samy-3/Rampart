package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

var (
	ErrUnauthorized = errors.New("auth: unauthorized")
	ErrForbidden    = errors.New("auth: forbidden")
)

// Role defines built-in Phase 1 tenant roles (D8, D14).
type Role string

const (
	RoleViewer  Role = "viewer"
	RoleTriager Role = "triager"
	// RoleMaintainer approves risk acceptances and manages what belongs to an application (docs/07).
	RoleMaintainer Role = "maintainer"
	// RoleOwner also manages access bindings in its scope (docs/07).
	RoleOwner Role = "owner"
	RoleAdmin Role = "admin"
)

// ParseRole returns a known role, or false.
func ParseRole(s string) (Role, bool) {
	switch r := Role(s); r {
	case RoleViewer, RoleTriager, RoleMaintainer, RoleOwner, RoleAdmin:
		return r, true
	}
	return "", false
}

func (r Role) Rank() int {
	switch r {
	case RoleAdmin:
		return 40
	case RoleOwner:
		return 30
	case RoleMaintainer:
		return 25
	case RoleTriager:
		return 20
	case RoleViewer:
		return 10
	default:
		return 0
	}
}

// TokenRecord holds the metadata associated with an issued API token (D8).
type TokenRecord struct {
	ID        uuid.UUID `json:"id"`
	TokenHash string    `json:"token_hash"`
	Subject   string    `json:"subject"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Role      Role      `json:"role"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type authContextKey struct{}

// ContextUser represents an authenticated caller in request context.
type ContextUser struct {
	Subject  string
	TenantID uuid.UUID
	Role     Role
	Scopes   []string

	// Set for browser sessions only (zero for API tokens).
	UserID    uuid.UUID
	Email     string
	Name      string
	SessionID uuid.UUID
}

// FromContext extracts the authenticated user from the context.
func FromContext(ctx context.Context) (*ContextUser, bool) {
	u, ok := ctx.Value(authContextKey{}).(*ContextUser)
	return u, ok
}

// TenantFromContext extracts the authenticated tenant UUID from context.
// Returns ErrUnauthorized if the context has no authenticated principal (eliminating blind X-Tenant-ID trust).
func TenantFromContext(ctx context.Context) (uuid.UUID, error) {
	u, ok := FromContext(ctx)
	if !ok || u.TenantID == domain.NilID {
		return domain.NilID, ErrUnauthorized
	}
	return u.TenantID, nil
}

// ContextWithUser injects an authenticated ContextUser into the context (primarily for testing and internal service calls).
func ContextWithUser(ctx context.Context, user *ContextUser) context.Context {
	return context.WithValue(ctx, authContextKey{}, user)
}

// HashToken computes the SHA-256 hexadecimal hash of a raw token string.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

const tokenPrefix = "rpt_"

// FormatToken builds the wire format rpt_<tenant-uuid-hex>_<secret>. The tenant is
// part of the token so the lookup can run under that tenant's RLS context (D4):
// api_token is a tenant table and an unset tenant sees zero rows. A caller can only
// ever find tokens of the tenant it names, and the record must carry the same tenant.
func FormatToken(tenantID uuid.UUID, secret string) string {
	return tokenPrefix + hex.EncodeToString(tenantID[:]) + "_" + secret
}

// TenantFromToken extracts the tenant named in a token without trusting it.
func TenantFromToken(rawToken string) (uuid.UUID, error) {
	rest, ok := strings.CutPrefix(rawToken, tokenPrefix)
	if !ok || len(rest) < 34 || rest[32] != '_' {
		return uuid.Nil, ErrUnauthorized
	}
	b, err := hex.DecodeString(rest[:32])
	if err != nil {
		return uuid.Nil, ErrUnauthorized
	}
	id, err := uuid.FromBytes(b)
	if err != nil || id == domain.NilID {
		return uuid.Nil, ErrUnauthorized
	}
	return id, nil
}

// GenerateToken generates a cryptographically random API token prefixed with 'rpt_' (D8)
// and returns both the plaintext secret and its hashed TokenRecord.
func GenerateToken(tenantID uuid.UUID, role Role, subject string, scopes []string, duration time.Duration) (string, *TokenRecord, error) {
	if tenantID == domain.NilID {
		return "", nil, domain.ErrInvalidTenantID
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", nil, fmt.Errorf("auth: failed to generate random token bytes: %w", err)
	}
	rawToken := FormatToken(tenantID, base64.RawURLEncoding.EncodeToString(rawBytes))
	hash := HashToken(rawToken)

	var expiresAt time.Time
	if duration > 0 {
		expiresAt = time.Now().UTC().Add(duration)
	}

	record := &TokenRecord{
		ID:        domain.NewID(),
		TokenHash: hash,
		Subject:   subject,
		TenantID:  tenantID,
		Role:      role,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}
	return rawToken, record, nil
}

// TokenStore abstracts persistent or memory-backed token lookup.
type TokenStore interface {
	LookupTokenByHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*TokenRecord, error)
	SaveToken(ctx context.Context, record *TokenRecord) error
}

// MemoryTokenStore provides a thread-safe in-memory TokenStore implementation.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenRecord // hash -> record
}

func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*TokenRecord),
	}
}

func (m *MemoryTokenStore) LookupTokenByHash(_ context.Context, tenantID uuid.UUID, tokenHash string) (*TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, exists := m.tokens[tokenHash]
	if !exists || record.TenantID != tenantID {
		return nil, ErrUnauthorized
	}
	return record, nil
}

func (m *MemoryTokenStore) SaveToken(_ context.Context, record *TokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[record.TokenHash] = record
	return nil
}

// Authenticator validates bearer tokens and enforces tenant RBAC.
type Authenticator struct {
	store    TokenStore
	sessions *SessionManager // optional: browser sessions (doc 14)
}

// SetSessions enables authentication by session cookie when a request carries no API token.
func (a *Authenticator) SetSessions(m *SessionManager) { a.sessions = m }

// NewAuthenticator creates a new authenticator instance with default in-memory store.
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		store: NewMemoryTokenStore(),
	}
}

// NewAuthenticatorWithStore creates an authenticator backed by a custom TokenStore (e.g. PostgresStore).
func NewAuthenticatorWithStore(store TokenStore) *Authenticator {
	return &Authenticator{
		store: store,
	}
}

// RegisterToken stores an active token by hashing it and persisting the record.
func (a *Authenticator) RegisterToken(rawToken string, record *TokenRecord) {
	record.TokenHash = HashToken(rawToken)
	if record.ID == domain.NilID {
		record.ID = domain.NewID()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	_ = a.store.SaveToken(context.Background(), record)
}

// AuthenticateRequest inspects the HTTP request and returns the authenticated user if valid.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*ContextUser, error) {
	token := extractToken(r)
	if token == "" {
		return a.authenticateSession(r)
	}

	tenantID, err := TenantFromToken(token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	record, err := a.store.LookupTokenByHash(r.Context(), tenantID, HashToken(token))
	if err != nil || record == nil || record.TenantID != tenantID {
		return nil, ErrUnauthorized
	}

	if !record.ExpiresAt.IsZero() && time.Now().After(record.ExpiresAt) {
		return nil, ErrUnauthorized
	}

	return &ContextUser{
		Subject:  record.Subject,
		TenantID: record.TenantID,
		Role:     record.Role,
		Scopes:   record.Scopes,
	}, nil
}

// authenticateSession authenticates a browser by its session cookie. State-changing methods
// additionally need the CSRF token bound to the session (doc 14, doc 13 section 3).
func (a *Authenticator) authenticateSession(r *http.Request) (*ContextUser, error) {
	if a.sessions == nil {
		return nil, ErrUnauthorized
	}
	p, err := a.sessions.Principal(r)
	if err != nil {
		return nil, ErrUnauthorized
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if !a.sessions.CheckCSRF(r, p.Session.ID) {
			return nil, ErrCSRF
		}
	}
	return &ContextUser{
		Subject: p.Email, TenantID: p.Session.TenantID, Role: p.Role, Scopes: []string{"tenant"},
		UserID: p.Session.UserID, Email: p.Email, Name: p.Name, SessionID: p.Session.ID,
	}, nil
}

// Middleware creates an HTTP middleware that extracts and validates the token.
// Rejects unauthenticated requests with 401 Unauthorized (eliminating blind tenant trust).
func (a *Authenticator) Middleware(allowUnauthenticated bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := a.AuthenticateRequest(r)
			if err != nil {
				if allowUnauthenticated {
					// Only for purely local bootstrapping when explicitly permitted
					tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
					user = &ContextUser{
						Subject:  "anonymous-local",
						TenantID: tenantID,
						Role:     RoleAdmin,
						Scopes:   []string{"*"},
					}
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
					return
				}
			}

			ctx := context.WithValue(r.Context(), authContextKey{}, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole checks that the authenticated user has at least the required role rank.
func RequireRole(required Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := FromContext(r.Context())
		if !ok || user.Role.Rank() < required.Rank() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/forbidden","title":"Insufficient permissions"}`))
			return
		}
		next(w, r)
	}
}

func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	return ""
}

// DefaultAdminToken creates an initial bootstrap admin token for a tenant with cryptographic security (D8).
func (a *Authenticator) DefaultAdminToken(tenantID uuid.UUID) string {
	rawToken, record, err := GenerateToken(tenantID, RoleAdmin, "admin@rampart.local", []string{"*"}, 365*24*time.Hour)
	if err != nil {
		// Fallback if crypto/rand fails
		rawToken = FormatToken(tenantID, domain.NewID().String())
		record = &TokenRecord{
			ID:        domain.NewID(),
			TokenHash: HashToken(rawToken),
			Subject:   "admin@rampart.local",
			TenantID:  tenantID,
			Role:      RoleAdmin,
			Scopes:    []string{"*"},
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}
	}
	_ = a.store.SaveToken(context.Background(), record)
	return rawToken
}
