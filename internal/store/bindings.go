package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"rampart/internal/domain"
)

// AccessBindings stores the per-application roles of docs/16 D48. Only the PostgreSQL store implements it.
type AccessBindings interface {
	// UpsertAccessBinding gives subject the role on the application; a second call for the same subject and
	// application replaces the role.
	UpsertAccessBinding(ctx context.Context, tenantID uuid.UUID, b *domain.AccessBinding) error
	ListAccessBindings(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID) ([]domain.AccessBinding, error)
	GetAccessBinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.AccessBinding, error)
	DeleteAccessBinding(ctx context.Context, tenantID, id uuid.UUID) error
	// BindingsFor returns the bindings whose subject is one of subjects (case-insensitive).
	BindingsFor(ctx context.Context, tenantID uuid.UUID, subjects []string) ([]domain.AccessBinding, error)
}

const bindingCols = `b.id, b.subject, b.role, coalesce(b.application_id, '00000000-0000-0000-0000-000000000000'::uuid), coalesce(a.name, ''), b.managed_by, b.created_by, b.created_at, coalesce(b.hierarchy_path, ''), b.tenant_scope, b.subject_kind, b.idp`

func scanBinding(row pgx.Row) (domain.AccessBinding, error) {
	var b domain.AccessBinding
	err := row.Scan(&b.ID, &b.Subject, &b.Role, &b.ApplicationID, &b.ApplicationName, &b.ManagedBy, &b.CreatedBy, &b.CreatedAt, &b.HierarchyPath, &b.TenantScope, &b.SubjectKind, &b.IdP)
	return b, err
}

func (s *PostgresStore) UpsertAccessBinding(ctx context.Context, tenantID uuid.UUID, b *domain.AccessBinding) error {
	if b.ID == uuid.Nil {
		b.ID = domain.NewID()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	if b.ManagedBy == "" {
		b.ManagedBy = "api"
	}
	if b.SubjectKind == "" {
		b.SubjectKind = "user"
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		if b.TenantScope {
			err = tx.QueryRow(ctx, `INSERT INTO access_binding (id, tenant_id, subject, role, application_id, managed_by, created_by, created_at, tenant_scope, subject_kind, idp)
				VALUES ($1,$2,$3,$4,NULL,$5,$6,$7,TRUE,$8,$9)
				ON CONFLICT (tenant_id, lower(subject)) WHERE tenant_scope = TRUE
				DO UPDATE SET role = EXCLUDED.role, created_by = EXCLUDED.created_by
				RETURNING id`, b.ID, tenantID, b.Subject, string(b.Role), b.ManagedBy, b.CreatedBy, b.CreatedAt, b.SubjectKind, b.IdP).Scan(&b.ID)
		} else if b.HierarchyPath != "" {
			err = tx.QueryRow(ctx, `INSERT INTO access_binding (id, tenant_id, subject, role, application_id, managed_by, created_by, created_at, hierarchy_path, subject_kind, idp)
				VALUES ($1,$2,$3,$4,NULL,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (tenant_id, lower(subject), hierarchy_path) WHERE hierarchy_path IS NOT NULL
				DO UPDATE SET role = EXCLUDED.role, created_by = EXCLUDED.created_by
				RETURNING id`, b.ID, tenantID, b.Subject, string(b.Role), b.ManagedBy, b.CreatedBy, b.CreatedAt, b.HierarchyPath, b.SubjectKind, b.IdP).Scan(&b.ID)
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO access_binding (id, tenant_id, subject, role, application_id, managed_by, created_by, created_at, subject_kind, idp)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (tenant_id, lower(subject), application_id) WHERE application_id IS NOT NULL
				DO UPDATE SET role = EXCLUDED.role, created_by = EXCLUDED.created_by
				RETURNING id`, b.ID, tenantID, b.Subject, string(b.Role), b.ApplicationID, b.ManagedBy, b.CreatedBy, b.CreatedAt, b.SubjectKind, b.IdP).Scan(&b.ID)
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23503" { // foreign key: the application is not there
			return ErrNotFound
		}
		return err
	})
}

func (s *PostgresStore) ListAccessBindings(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID) ([]domain.AccessBinding, error) {
	out := []domain.AccessBinding{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+bindingCols+` FROM access_binding b LEFT JOIN application a ON a.id = b.application_id
			WHERE b.tenant_id = $1 AND ($2::uuid IS NULL OR b.application_id = $2) ORDER BY a.name, lower(b.subject)`, tenantID, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanBinding(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) GetAccessBinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.AccessBinding, error) {
	var out *domain.AccessBinding
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		b, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingCols+` FROM access_binding b LEFT JOIN application a ON a.id = b.application_id
			WHERE b.tenant_id = $1 AND b.id = $2`, tenantID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		out = &b
		return err
	})
	return out, err
}

func (s *PostgresStore) DeleteAccessBinding(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM access_binding WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (s *PostgresStore) BindingsFor(ctx context.Context, tenantID uuid.UUID, subjects []string) ([]domain.AccessBinding, error) {
	lower := make([]string, 0, len(subjects))
	for _, s := range subjects {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			lower = append(lower, s)
		}
	}
	out := []domain.AccessBinding{}
	if len(lower) == 0 {
		return out, nil
	}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+bindingCols+` FROM access_binding b LEFT JOIN application a ON a.id = b.application_id
			WHERE b.tenant_id = $1 AND lower(b.subject) = ANY($2)`, tenantID, lower)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanBinding(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}
