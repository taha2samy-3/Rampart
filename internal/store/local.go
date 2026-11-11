package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// GetLocalAdmin returns a local account, or (nil, nil).
func (s *PostgresStore) GetLocalAdmin(ctx context.Context, tenantID uuid.UUID, username string) (*auth.LocalAdmin, error) {
	var a auth.LocalAdmin
	var userID *uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, user_id, username, password_hash, failed_attempts, locked_until
			FROM local_admin WHERE tenant_id = $1 AND username = $2`, tenantID, username).Scan(
			&a.ID, &a.TenantID, &userID, &a.Username, &a.PasswordHash, &a.FailedAttempts, &a.LockedUntil)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if userID != nil {
		a.UserID = *userID
	}
	return &a, nil
}

// CreateLocalAdmin inserts the account once; an existing account is left alone (false, nil).
func (s *PostgresStore) CreateLocalAdmin(ctx context.Context, a auth.LocalAdmin) (bool, error) {
	created := false
	err := s.withTenantTx(ctx, a.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO local_admin (id, tenant_id, user_id, username, password_hash)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, username) DO NOTHING`,
			a.ID, a.TenantID, a.UserID, a.Username, a.PasswordHash)
		created = err == nil && tag.RowsAffected() == 1
		return err
	})
	return created, err
}

// RecordLocalLogin updates the failure counter in one statement, so two simultaneous wrong guesses
// cannot both read the same count and slip past the lock. Success resets the counter; the failure
// that reaches maxFailures sets locked_until.
func (s *PostgresStore) RecordLocalLogin(ctx context.Context, tenantID, id uuid.UUID, success bool, now time.Time, maxFailures int, lock time.Duration) (*time.Time, error) {
	var locked *time.Time
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if success {
			_, err := tx.Exec(ctx, `UPDATE local_admin SET failed_attempts = 0, locked_until = NULL, last_login = $3
				WHERE tenant_id = $1 AND id = $2`, tenantID, id, now)
			return err
		}
		return tx.QueryRow(ctx, `
			UPDATE local_admin SET
				failed_attempts = CASE WHEN failed_attempts + 1 >= $3 THEN 0 ELSE failed_attempts + 1 END,
				locked_until    = CASE WHEN failed_attempts + 1 >= $3 THEN $4::timestamptz ELSE locked_until END
			WHERE tenant_id = $1 AND id = $2
			RETURNING CASE WHEN failed_attempts = 0 THEN locked_until END`,
			tenantID, id, maxFailures, now.Add(lock)).Scan(&locked)
	})
	return locked, err
}

// SetLocalAdminPassword replaces the hash and clears the lock (CLI recovery).
func (s *PostgresStore) SetLocalAdminPassword(ctx context.Context, tenantID uuid.UUID, username, passwordHash string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE local_admin SET password_hash = $3, failed_attempts = 0, locked_until = NULL, password_changed_at = now()
			WHERE tenant_id = $1 AND username = $2`, tenantID, username, passwordHash)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// RecordAudit appends an authentication event to the partitioned audit log.
func (s *PostgresStore) RecordAudit(ctx context.Context, e auth.AuditEvent) error {
	actor, _ := json.Marshal(map[string]string{"id": e.Actor})
	var detail []byte
	if e.Detail != nil {
		detail, _ = json.Marshal(e.Detail)
	}
	var ip *netip.Addr
	if a, err := netip.ParseAddr(e.IP); err == nil {
		ip = &a
	}
	return s.withTenantTx(ctx, e.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO audit_event (id, tenant_id, actor, action, resource_type, resource_id, after, ip, user_agent, request_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			domain.NewID(), e.TenantID, actor, e.Action, e.ResourceType, e.ResourceID, detail, ip, e.UserAgent, e.RequestID)
		return err
	})
}
