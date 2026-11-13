package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"rampart/internal/domain"
)

var (
	ErrJTIReplay = errors.New("federation: token replay detected, jti already used")
)

// Federation defines persistence for CI OIDC federation rules and replay prevention (D22).
type Federation interface {
	SaveTrustRules(ctx context.Context, tenantID, scanSourceID uuid.UUID, rules []domain.TrustRule) error
	ListTrustRules(ctx context.Context, tenantID uuid.UUID) ([]domain.TrustRuleRecord, error)
	ListTrustRulesByIssuer(ctx context.Context, tenantID uuid.UUID, issuer string) ([]domain.TrustRuleRecord, error)
	RecordFederationJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) error
	PurgeExpiredFederationJTIs(ctx context.Context, now time.Time) (int64, error)
}

// SaveTrustRules replaces the trust rules for a ScanSource under tenant RLS.
func (s *PostgresStore) SaveTrustRules(ctx context.Context, tenantID, scanSourceID uuid.UUID, rules []domain.TrustRule) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM source_trust WHERE tenant_id = $1 AND scan_source_id = $2`, tenantID, scanSourceID); err != nil {
			return fmt.Errorf("store: failed to clear existing trust rules: %w", err)
		}
		for _, r := range rules {
			id := domain.NewID()
			var repoID, ownerID, projID, nsID, repo *string
			if r.RepositoryID != "" {
				repoID = &r.RepositoryID
			}
			if r.RepositoryOwnerID != "" {
				ownerID = &r.RepositoryOwnerID
			}
			if r.ProjectID != "" {
				projID = &r.ProjectID
			}
			if r.NamespaceID != "" {
				nsID = &r.NamespaceID
			}
			if r.Repository != "" {
				repo = &r.Repository
			}

			_, err := tx.Exec(ctx, `
				INSERT INTO source_trust (id, tenant_id, scan_source_id, issuer, provider, repository_id, repository_owner_id, project_id, namespace_id, repository, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
				id, tenantID, scanSourceID, r.Issuer, r.Provider, repoID, ownerID, projID, nsID, repo)
			if err != nil {
				return fmt.Errorf("store: failed to insert trust rule: %w", err)
			}
		}
		return nil
	})
}

// ListTrustRules returns all trust rules for a tenant.
func (s *PostgresStore) ListTrustRules(ctx context.Context, tenantID uuid.UUID) ([]domain.TrustRuleRecord, error) {
	var records []domain.TrustRuleRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, scan_source_id, issuer, provider,
			       coalesce(repository_id, ''), coalesce(repository_owner_id, ''),
			       coalesce(project_id, ''), coalesce(namespace_id, ''),
			       coalesce(repository, ''), created_at
			FROM source_trust
			WHERE tenant_id = $1
			ORDER BY created_at ASC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var rec domain.TrustRuleRecord
			if err := rows.Scan(
				&rec.ID, &rec.TenantID, &rec.ScanSourceID,
				&rec.Rule.Issuer, &rec.Rule.Provider,
				&rec.Rule.RepositoryID, &rec.Rule.RepositoryOwnerID,
				&rec.Rule.ProjectID, &rec.Rule.NamespaceID,
				&rec.Rule.Repository, &rec.CreatedAt,
			); err != nil {
				return err
			}
			records = append(records, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: failed to list trust rules: %w", err)
	}
	return records, nil
}

// ListTrustRulesByIssuer returns all trust rules for a tenant and specific issuer.
func (s *PostgresStore) ListTrustRulesByIssuer(ctx context.Context, tenantID uuid.UUID, issuer string) ([]domain.TrustRuleRecord, error) {
	var records []domain.TrustRuleRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, scan_source_id, issuer, provider,
			       coalesce(repository_id, ''), coalesce(repository_owner_id, ''),
			       coalesce(project_id, ''), coalesce(namespace_id, ''),
			       coalesce(repository, ''), created_at
			FROM source_trust
			WHERE tenant_id = $1 AND issuer = $2
			ORDER BY created_at ASC`, tenantID, issuer)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var rec domain.TrustRuleRecord
			if err := rows.Scan(
				&rec.ID, &rec.TenantID, &rec.ScanSourceID,
				&rec.Rule.Issuer, &rec.Rule.Provider,
				&rec.Rule.RepositoryID, &rec.Rule.RepositoryOwnerID,
				&rec.Rule.ProjectID, &rec.Rule.NamespaceID,
				&rec.Rule.Repository, &rec.CreatedAt,
			); err != nil {
				return err
			}
			records = append(records, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: failed to list trust rules by issuer: %w", err)
	}
	return records, nil
}

// RecordFederationJTI records an exchanged token JTI globally across tenants to prevent replays (D22).
func (s *PostgresStore) RecordFederationJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO federation_jti (issuer, jti, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())`,
		issuer, jti, expiresAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrJTIReplay
		}
		return fmt.Errorf("store: failed to record federation jti: %w", err)
	}
	return nil
}

// PurgeExpiredFederationJTIs deletes expired JTI records from the replay table.
func (s *PostgresStore) PurgeExpiredFederationJTIs(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM federation_jti WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("store: failed to purge expired federation jtis: %w", err)
	}
	return tag.RowsAffected(), nil
}
