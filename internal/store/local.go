package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// SetLocalAdminPassword replaces the hash, clears the lock, and ends every session of the account in
// the same transaction: after a password change nobody keeps a session opened with the old one.
func (s *PostgresStore) SetLocalAdminPassword(ctx context.Context, tenantID uuid.UUID, username, passwordHash string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var userID *uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE local_admin SET password_hash = $3, failed_attempts = 0, locked_until = NULL, password_changed_at = now()
			WHERE tenant_id = $1 AND username = $2 RETURNING user_id`, tenantID, username, passwordHash).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if userID != nil {
			_, err = tx.Exec(ctx, `DELETE FROM session WHERE tenant_id = $1 AND user_id = $2`, tenantID, *userID)
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

// ErrUploadExists is returned by CreateUpload when the idempotency key is already taken in the tenant.
var ErrUploadExists = errors.New("store: an upload with this idempotency key exists")

// CreateUpload inserts an upload in status created.
func (s *PostgresStore) CreateUpload(ctx context.Context, u *domain.Upload) error {
	ctxJSON, _ := json.Marshal(u.Context)
	var key *string
	if u.IdempotencyKey != "" {
		key = &u.IdempotencyKey
	}
	var src *uuid.UUID
	if u.ScanSourceID != uuid.Nil {
		src = &u.ScanSourceID
	}
	err := s.withTenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO upload (id, tenant_id, scan_source_id, idempotency_key, request_hash, object_ref, sha256, size_bytes, format_hint, context, status, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			u.ID, u.TenantID, src, key, u.RequestHash, u.ObjectRef, u.SHA256, u.SizeBytes, u.FormatHint, ctxJSON, u.Status, u.CreatedAt)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && key != nil {
		return ErrUploadExists
	}
	return err
}

const uploadCols = `id, tenant_id, scan_source_id, coalesce(idempotency_key, ''), request_hash, object_ref, sha256, size_bytes, coalesce(format_hint, ''), context, status, created_at`

func scanUpload(row pgx.Row) (*domain.Upload, error) {
	var u domain.Upload
	var src *uuid.UUID
	var ctxJSON []byte
	if err := row.Scan(&u.ID, &u.TenantID, &src, &u.IdempotencyKey, &u.RequestHash, &u.ObjectRef, &u.SHA256, &u.SizeBytes, &u.FormatHint, &ctxJSON, &u.Status, &u.CreatedAt); err != nil {
		return nil, err
	}
	if src != nil {
		u.ScanSourceID = *src
	}
	_ = json.Unmarshal(ctxJSON, &u.Context)
	return &u, nil
}

// GetUpload returns an upload, or ErrNotFound.
func (s *PostgresStore) GetUpload(ctx context.Context, tenantID, id uuid.UUID) (*domain.Upload, error) {
	var u *domain.Upload
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		u, err = scanUpload(tx.QueryRow(ctx, `SELECT `+uploadCols+` FROM upload WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// FindUploadByKey returns the upload with an idempotency key, or (nil, nil).
func (s *PostgresStore) FindUploadByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Upload, error) {
	var u *domain.Upload
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		u, err = scanUpload(tx.QueryRow(ctx, `SELECT `+uploadCols+` FROM upload WHERE tenant_id = $1 AND idempotency_key = $2`, tenantID, key))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// DeleteUpload removes an upload (an expired idempotency key being replaced).
func (s *PostgresStore) DeleteUpload(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM upload WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}

// CompleteUpload flips created to completed in one statement, so two concurrent `complete` calls
// cannot both win; the loser sees false.
func (s *PostgresStore) CompleteUpload(ctx context.Context, tenantID, id uuid.UUID, sha256 string) (bool, error) {
	done := false
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE upload SET status = 'completed', sha256 = $3 WHERE tenant_id = $1 AND id = $2 AND status = 'created'`, tenantID, id, sha256)
		done = err == nil && tag.RowsAffected() == 1
		return err
	})
	return done, err
}

// FindRunByUpload returns the ingest run created by an upload's `complete`, or (nil, nil).
func (s *PostgresStore) FindRunByUpload(ctx context.Context, tenantID, uploadID uuid.UUID) (*domain.IngestRun, error) {
	var id uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM ingest_run WHERE tenant_id = $1 AND upload_id = $2 ORDER BY created_at LIMIT 1`, tenantID, uploadID).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetIngestRun(ctx, tenantID, id)
}

// PgxTx returns the pgx transaction when this store was handed out by InTenantTx, so work that must
// commit with it (a River job insert, D2) can join it. It is nil outside a transaction.
func (s *PostgresStore) PgxTx() pgx.Tx { return s.tx }
