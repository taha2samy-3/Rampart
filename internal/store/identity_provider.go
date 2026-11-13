package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// IdentityProviders manages tenant-scoped and platform-wide identity providers (docs/04, docs/14, docs/16 D8, D27, D64).
type IdentityProviders interface {
	SaveIdentityProvider(ctx context.Context, tenantID *uuid.UUID, idp domain.IdentityProvider) error
	GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error)
	ListIdentityProviders(ctx context.Context, tenantID *uuid.UUID) ([]domain.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) error
	ApproveDomainClaim(ctx context.Context, tenantID *uuid.UUID, name, domainName string) error
}

func (s *PostgresStore) SaveIdentityProvider(ctx context.Context, tenantID *uuid.UUID, idp domain.IdentityProvider) error {
	if idp.ID == uuid.Nil {
		idp.ID = domain.NewID()
	}
	now := time.Now().UTC()
	if idp.CreatedAt.IsZero() {
		idp.CreatedAt = now
	}
	idp.UpdatedAt = now

	specJSON, err := json.Marshal(idp.Spec)
	if err != nil {
		return err
	}
	statusJSON, err := json.Marshal(idp.Status)
	if err != nil {
		return err
	}

	allowedTenants := idp.Spec.AllowedTenants
	if allowedTenants == nil {
		allowedTenants = []string{}
	}

	typeName := string(idp.Type)
	if typeName == "" {
		typeName = "oidc"
	}

	return s.withSystemTx(ctx, func(tx pgx.Tx) error {
		if tenantID != nil {
			_, err := tx.Exec(ctx, `
				INSERT INTO identity_provider (id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10)
				ON CONFLICT (tenant_id, name) WHERE tenant_id IS NOT NULL
				DO UPDATE SET
					display_name = EXCLUDED.display_name,
					type = EXCLUDED.type,
					allowed_tenants = EXCLUDED.allowed_tenants,
					spec = EXCLUDED.spec,
					status = EXCLUDED.status,
					updated_at = EXCLUDED.updated_at`,
				idp.ID, *tenantID, idp.Name, idp.DisplayName, typeName, allowedTenants, specJSON, statusJSON, idp.CreatedAt, idp.UpdatedAt)
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO identity_provider (id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at)
			VALUES ($1, NULL, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9)
			ON CONFLICT (name) WHERE tenant_id IS NULL
			DO UPDATE SET
				display_name = EXCLUDED.display_name,
				type = EXCLUDED.type,
				allowed_tenants = EXCLUDED.allowed_tenants,
				spec = EXCLUDED.spec,
				status = EXCLUDED.status,
				updated_at = EXCLUDED.updated_at`,
			idp.ID, idp.Name, idp.DisplayName, typeName, allowedTenants, specJSON, statusJSON, idp.CreatedAt, idp.UpdatedAt)
		return err
	})
}

func (s *PostgresStore) GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error) {
	var idp domain.IdentityProvider
	var tid *uuid.UUID
	var specRaw, statusRaw []byte
	var allowedTenants []string
	var typeStr string

	err := s.withSystemTx(ctx, func(tx pgx.Tx) error {
		var row pgx.Row
		if tenantID != nil {
			// First look for a tenant-scoped provider
			row = tx.QueryRow(ctx, `
				SELECT id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at
				FROM identity_provider
				WHERE tenant_id = $1 AND name = $2`, *tenantID, name)
			err := row.Scan(&idp.ID, &tid, &idp.Name, &idp.DisplayName, &typeStr, &allowedTenants, &specRaw, &statusRaw, &idp.CreatedAt, &idp.UpdatedAt)
			if err == nil {
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			// If not found at tenant scope, fallback to cluster scope
		}
		row = tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at
			FROM identity_provider
			WHERE tenant_id IS NULL AND name = $1`, name)
		return row.Scan(&idp.ID, &tid, &idp.Name, &idp.DisplayName, &typeStr, &allowedTenants, &specRaw, &statusRaw, &idp.CreatedAt, &idp.UpdatedAt)
	})

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	idp.TenantID = tid
	idp.Type = domain.IdPType(typeStr)
	if err := json.Unmarshal(specRaw, &idp.Spec); err != nil {
		return nil, err
	}
	idp.Spec.AllowedTenants = allowedTenants
	if len(statusRaw) > 0 {
		_ = json.Unmarshal(statusRaw, &idp.Status)
	}
	return &idp, nil
}

func (s *PostgresStore) ListIdentityProviders(ctx context.Context, tenantID *uuid.UUID) ([]domain.IdentityProvider, error) {
	var list []domain.IdentityProvider

	err := s.withSystemTx(ctx, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error
		if tenantID != nil {
			// List tenant providers and all cluster providers
			rows, err = tx.Query(ctx, `
				SELECT id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at
				FROM identity_provider
				WHERE tenant_id = $1 OR tenant_id IS NULL
				ORDER BY (tenant_id IS NOT NULL) DESC, name ASC`, *tenantID)
		} else {
			// Cluster-wide only
			rows, err = tx.Query(ctx, `
				SELECT id, tenant_id, name, display_name, type, allowed_tenants, spec, status, created_at, updated_at
				FROM identity_provider
				WHERE tenant_id IS NULL
				ORDER BY name ASC`)
		}
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var idp domain.IdentityProvider
			var tid *uuid.UUID
			var specRaw, statusRaw []byte
			var allowedTenants []string
			var typeStr string

			if err := rows.Scan(&idp.ID, &tid, &idp.Name, &idp.DisplayName, &typeStr, &allowedTenants, &specRaw, &statusRaw, &idp.CreatedAt, &idp.UpdatedAt); err != nil {
				return err
			}
			idp.TenantID = tid
			idp.Type = domain.IdPType(typeStr)
			if err := json.Unmarshal(specRaw, &idp.Spec); err != nil {
				return err
			}
			idp.Spec.AllowedTenants = allowedTenants
			if len(statusRaw) > 0 {
				_ = json.Unmarshal(statusRaw, &idp.Status)
			}
			list = append(list, idp)
		}
		return rows.Err()
	})

	if err != nil {
		return nil, err
	}
	return list, nil
}

func (s *PostgresStore) DeleteIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) error {
	return s.withSystemTx(ctx, func(tx pgx.Tx) error {
		var err error
		if tenantID != nil {
			_, err = tx.Exec(ctx, `DELETE FROM identity_provider WHERE tenant_id = $1 AND name = $2`, *tenantID, name)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM identity_provider WHERE tenant_id IS NULL AND name = $1`, name)
		}
		return err
	})
}

// ApproveDomainClaim verifies or platform-approves an email domain claim on an IdentityProvider (docs/16 D27).
func (s *PostgresStore) ApproveDomainClaim(ctx context.Context, tenantID *uuid.UUID, name, domainName string) error {
	idp, err := s.GetIdentityProvider(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if idp == nil {
		return ErrNotFound
	}

	found := false
	now := time.Now().UTC()
	for i := range idp.Status.Domains {
		if idp.Status.Domains[i].Domain == domainName {
			idp.Status.Domains[i].Approved = true
			idp.Status.Domains[i].VerifiedAt = &now
			found = true
			break
		}
	}
	if !found {
		idp.Status.Domains = append(idp.Status.Domains, domain.DomainClaimStatus{
			Domain:     domainName,
			Approved:   true,
			VerifiedAt: &now,
		})
	}
	return s.SaveIdentityProvider(ctx, tenantID, *idp)
}
