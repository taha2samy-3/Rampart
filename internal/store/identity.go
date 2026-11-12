package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// UpsertUser creates or updates the global person row for (issuer, subject) (D8). app_user has no RLS.
func (s *PostgresStore) UpsertUser(ctx context.Context, u auth.User) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_user (id, issuer, subject, email, display_name, last_login)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (issuer, subject) DO UPDATE SET
			email = EXCLUDED.email, display_name = EXCLUDED.display_name, last_login = now()
		RETURNING id`, domain.NewID(), u.Issuer, u.Subject, u.Email, u.Name).Scan(&id)
	return id, err
}

// UpsertMember sets the role of a person in a tenant (tenant_member, under that tenant's RLS).
func (s *PostgresStore) UpsertMember(ctx context.Context, tenantID, userID uuid.UUID, role auth.Role) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_member (tenant_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role`, tenantID, userID, string(role))
		return err
	})
}

// GetMemberRole returns the role of a person in a tenant and whether they are a member.
func (s *PostgresStore) GetMemberRole(ctx context.Context, tenantID, userID uuid.UUID) (auth.Role, bool, error) {
	var role string
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role FROM tenant_member WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID).Scan(&role)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return auth.Role(role), true, nil
}

// ListUserTenants lists the tenants a person belongs to. tenant_member is under row-level
// security, so this runs with app.user_id set; the member_reads_own policy then exposes only the
// caller's own rows.
func (s *PostgresStore) ListUserTenants(ctx context.Context, userID uuid.UUID) ([]auth.TenantRef, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, userID.String()); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT t.id, t.slug, t.display_name FROM tenant_member m
		JOIN tenant t ON t.id = m.tenant_id WHERE m.user_id = $1 ORDER BY t.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auth.TenantRef{}
	for rows.Next() {
		var t auth.TenantRef
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateSession stores a session (hash only) under its tenant.
func (s *PostgresStore) CreateSession(ctx context.Context, r auth.SessionRecord) error {
	return s.withTenantTx(ctx, r.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO session (id, tenant_id, user_id, token_hash, expires_at, last_seen_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			r.ID, r.TenantID, r.UserID, r.TokenHash, r.ExpiresAt, r.LastSeenAt, r.CreatedAt)
		return err
	})
}

// LookupSession finds a session by token hash and joins the person and the role they hold in the
// tenant. A removed membership or a disabled user yields no row, which revokes the session at once.
func (s *PostgresStore) LookupSession(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*auth.SessionPrincipal, error) {
	var p auth.SessionPrincipal
	var role string
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT s.id, s.tenant_id, s.user_id, s.token_hash, s.expires_at, s.last_seen_at, s.created_at,
			       coalesce(u.email, ''), coalesce(u.display_name, ''), m.role
			FROM session s
			JOIN app_user u ON u.id = s.user_id AND u.status = 'active'
			JOIN tenant_member m ON m.tenant_id = s.tenant_id AND m.user_id = s.user_id
			WHERE s.tenant_id = $1 AND s.token_hash = $2`, tenantID, tokenHash).Scan(
			&p.Session.ID, &p.Session.TenantID, &p.Session.UserID, &p.Session.TokenHash,
			&p.Session.ExpiresAt, &p.Session.LastSeenAt, &p.Session.CreatedAt, &p.Email, &p.Name, &role)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	p.Role = auth.Role(role)
	return &p, nil
}

// TouchSession records activity for the idle timeout.
func (s *PostgresStore) TouchSession(ctx context.Context, tenantID, sessionID uuid.UUID, at time.Time) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE session SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, sessionID, at)
		return err
	})
}

// DeleteSession ends a session.
func (s *PostgresStore) DeleteSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM session WHERE tenant_id = $1 AND id = $2`, tenantID, sessionID)
		return err
	})
}

// IsTenantMemberEmail says whether an active person with this e-mail (any case) is a member of the tenant (D59).
func (s *PostgresStore) IsTenantMemberEmail(ctx context.Context, tenantID uuid.UUID, email string) (bool, error) {
	var ok bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM tenant_member m JOIN app_user u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND lower(u.email) = lower($2) AND u.status = 'active')`, tenantID, email).Scan(&ok)
	})
	return ok, err
}
