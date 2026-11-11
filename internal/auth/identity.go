package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// User is a person known to the platform: one global row per (issuer, subject) (D8).
type User struct {
	ID      uuid.UUID
	Issuer  string
	Subject string
	Email   string
	Name    string
}

// TenantRef is a tenant a person may switch to.
type TenantRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// SessionRecord is a browser session (doc 14 section 2). The secret is never stored, only its hash.
type SessionRecord struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time // absolute lifetime
	LastSeenAt time.Time // idle timeout
	CreatedAt  time.Time
}

// SessionPrincipal is a session joined with the person and the role they hold in the session's tenant.
// A removed membership or a disabled user makes the lookup fail, which revokes the session.
type SessionPrincipal struct {
	Session SessionRecord
	Email   string
	Name    string
	Role    Role
}

// IdentityStore persists people, memberships and sessions (D8). Implemented by the PostgreSQL
// store (tenant tables under row-level security) and by the in-memory store.
type IdentityStore interface {
	UpsertUser(ctx context.Context, u User) (uuid.UUID, error)
	UpsertMember(ctx context.Context, tenantID, userID uuid.UUID, role Role) error
	GetMemberRole(ctx context.Context, tenantID, userID uuid.UUID) (Role, bool, error)
	ListUserTenants(ctx context.Context, userID uuid.UUID) ([]TenantRef, error)

	CreateSession(ctx context.Context, s SessionRecord) error
	LookupSession(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*SessionPrincipal, error)
	TouchSession(ctx context.Context, tenantID, sessionID uuid.UUID, at time.Time) error
	DeleteSession(ctx context.Context, tenantID, sessionID uuid.UUID) error
}

// Binding grants a role to a person or a group at tenant scope. It is the Phase 1 form of an
// AccessBinding (D8): roles are never read straight from the IdP, they come from these rules.
type Binding struct {
	Kind string `json:"kind" yaml:"kind"` // user | group
	Name string `json:"name" yaml:"name"` // email or subject for a user, group name for a group
	Role Role   `json:"role" yaml:"role"`
}

// RolePolicy decides the role a person gets in a tenant at login.
type RolePolicy struct {
	// DefaultRole is given on first login when no binding matches. Empty means no access.
	DefaultRole Role
	Bindings    []Binding
}

// Resolve returns the strongest bound role; otherwise the role the person already holds;
// otherwise the default role. An empty result means the person may not enter the tenant.
func (p RolePolicy) Resolve(email, subject string, groups []string, existing Role) Role {
	best := Role("")
	consider := func(r Role) {
		if r.Rank() > best.Rank() {
			best = r
		}
	}
	inGroup := make(map[string]bool, len(groups))
	for _, g := range groups {
		inGroup[g] = true
	}
	for _, b := range p.Bindings {
		switch b.Kind {
		case "user":
			if b.Name != "" && (b.Name == email || b.Name == subject) {
				consider(b.Role)
			}
		case "group":
			if inGroup[b.Name] {
				consider(b.Role)
			}
		}
	}
	if best != "" {
		return best
	}
	if existing != "" {
		return existing
	}
	return p.DefaultRole
}
