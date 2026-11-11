package auth

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Local sign-in is the break-glass account of D3 and doc 14 section 1: one local administrator per
// tenant, created at first boot from a bootstrap secret, audited on every use, and switched off once
// an identity provider is configured unless keepEnabled says otherwise. It is not a user directory:
// password policy, MFA and recovery for everyone else belong to the identity provider.
const (
	// LocalIssuer is the issuer of the person rows behind local accounts.
	LocalIssuer = "rampart:local"

	maxFailedAttempts = 5
	lockDuration      = 15 * time.Minute
)

// LocalAdmin is a local account.
type LocalAdmin struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	UserID         uuid.UUID
	Username       string
	PasswordHash   string
	FailedAttempts int
	LockedUntil    *time.Time
}

// LocalAdminStore persists local accounts (under the tenant's row-level security).
type LocalAdminStore interface {
	// GetLocalAdmin returns the account, or (nil, nil) when there is none.
	GetLocalAdmin(ctx context.Context, tenantID uuid.UUID, username string) (*LocalAdmin, error)
	// CreateLocalAdmin inserts the account; it reports false, with no error, when it already exists.
	CreateLocalAdmin(ctx context.Context, a LocalAdmin) (bool, error)
	// RecordLocalLogin updates the failure counter atomically: success resets it; the fifth
	// consecutive failure locks the account until now+lock. It returns the locked-until time, if any.
	RecordLocalLogin(ctx context.Context, tenantID, id uuid.UUID, success bool, now time.Time, maxFailures int, lock time.Duration) (*time.Time, error)
	// SetLocalAdminPassword replaces the hash and clears any lock (operator recovery).
	SetLocalAdminPassword(ctx context.Context, tenantID uuid.UUID, username, passwordHash string) error
}

// AuditEvent is one entry of the audit log (doc 14 section 10: every authentication event).
type AuditEvent struct {
	TenantID     uuid.UUID
	Actor        string // for example "local:admin" or "anonymous"
	Action       string // local_login_success, local_login_failed, local_login_locked, local_login_disabled ...
	ResourceType string
	ResourceID   string
	Detail       map[string]any
	IP           string
	UserAgent    string
	RequestID    string
}

// AuditStore appends to the audit log.
type AuditStore interface {
	RecordAudit(ctx context.Context, e AuditEvent) error
}

// RateLimiter is a small sliding-window limiter keyed by client address. It slows password guessing
// from one source; the per-account lockout in the database covers the distributed case and holds
// across replicas.
type RateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
}

// NewRateLimiter allows max events per key per window.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, hits: map[string][]time.Time{}, now: time.Now}
}

// Allow records an attempt for key and reports whether it is within the limit; when it is not, it
// also returns how long until the next attempt would be allowed.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false, l.window - now.Sub(kept[0])
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 10000 { // bound memory under a spray from many addresses
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
	return true, 0
}
