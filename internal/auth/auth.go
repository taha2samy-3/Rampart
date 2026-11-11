package auth

import (
	"context"
	"errors"
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
	RoleAdmin   Role = "admin"
)

func (r Role) Rank() int {
	switch r {
	case RoleAdmin:
		return 30
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
	TokenHash string    `json:"token_hash"`
	Subject   string    `json:"subject"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Role      Role      `json:"role"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

type authContextKey struct{}

// ContextUser represents an authenticated caller in request context.
type ContextUser struct {
	Subject  string
	TenantID uuid.UUID
	Role     Role
	Scopes   []string
}

// FromContext extracts the authenticated user from the context.
func FromContext(ctx context.Context) (*ContextUser, bool) {
	u, ok := ctx.Value(authContextKey{}).(*ContextUser)
	return u, ok
}

// Authenticator validates bearer tokens and enforces tenant RBAC.
type Authenticator struct {
	mu     sync.RWMutex
	tokens map[string]*TokenRecord // token string -> record
}

// NewAuthenticator creates a new authenticator instance.
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		tokens: make(map[string]*TokenRecord),
	}
}

// RegisterToken stores an active token in the authenticator.
func (a *Authenticator) RegisterToken(token string, record *TokenRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[token] = record
}

// AuthenticateRequest inspects the HTTP request and returns the authenticated user if valid.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*ContextUser, error) {
	token := extractToken(r)
	if token == "" {
		return nil, ErrUnauthorized
	}

	a.mu.RLock()
	record, exists := a.tokens[token]
	a.mu.RUnlock()

	if !exists {
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

// Middleware creates an HTTP middleware that extracts and validates the token.
// If allowUnauthenticated is true, missing token falls back to default tenant admin (for local dev mode).
func (a *Authenticator) Middleware(allowUnauthenticated bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := a.AuthenticateRequest(r)
			if err != nil {
				if allowUnauthenticated {
					// Fallback to anonymous admin in local mode
					tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
					if tHeader := r.Header.Get("X-Tenant-ID"); tHeader != "" {
						if parsed, err := uuid.Parse(tHeader); err == nil {
							tenantID = parsed
						}
					}
					user = &ContextUser{
						Subject:  "anonymous-local",
						TenantID: tenantID,
						Role:     RoleAdmin,
						Scopes:   []string{"*"},
					}
				} else {
					http.Error(w, `{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`, http.StatusUnauthorized)
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
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/forbidden","title":"Insufficient permissions"}`, http.StatusForbidden)
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

// DefaultAdminToken creates an initial bootstrap admin token for a tenant.
func (a *Authenticator) DefaultAdminToken(tenantID uuid.UUID) string {
	token := "rampart_" + domain.NewID().String()
	a.RegisterToken(token, &TokenRecord{
		Subject:   "admin@rampart.local",
		TenantID:  tenantID,
		Role:      RoleAdmin,
		Scopes:    []string{"*"},
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	})
	return token
}
