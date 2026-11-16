package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// GroupStore defines persistence for finding groups (docs/21 §6.1).
type GroupStore interface {
	CreateFindingGroup(ctx context.Context, g *domain.FindingGroup) error
	GetFindingGroup(ctx context.Context, tenantID, id uuid.UUID) (*domain.FindingGroup, error)
	ListFindingGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.FindingGroup, error)
	DeleteFindingGroup(ctx context.Context, tenantID, id uuid.UUID) error
	AddGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error
	RemoveGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error
	ListGroupFindings(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error)
	// GroupMemberApplications returns the distinct applications of the group's findings (D90).
	GroupMemberApplications(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error)
	// RequestGroupTicket reserves the group's ticket for the sweeper. It returns false when a ticket is already
	// reserved or open; a failed one may be requested again (D90).
	RequestGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, requestedBy string) (bool, error)
}

// ViewStore defines persistence for saved views (docs/21 §6.2).
type ViewStore interface {
	CreateSavedView(ctx context.Context, v *domain.SavedView) error
	GetSavedView(ctx context.Context, tenantID, id uuid.UUID) (*domain.SavedView, error)
	ListSavedViews(ctx context.Context, tenantID uuid.UUID, owner string) ([]domain.SavedView, error)
	DeleteSavedView(ctx context.Context, tenantID, id uuid.UUID) error
}

// CreateFindingGroup creates a new finding group.
func (s *PostgresStore) CreateFindingGroup(ctx context.Context, g *domain.FindingGroup) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	g.CreatedAt = time.Now()
	g.UpdatedAt = g.CreatedAt

	return s.withTenantTx(ctx, g.TenantID, func(tx pgx.Tx) error {
		query := `INSERT INTO finding_group (id, tenant_id, name, description, owner, application_id, created_at, updated_at)
		          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err := tx.Exec(ctx, query, g.ID, g.TenantID, g.Name, g.Description, g.Owner, g.ApplicationID, g.CreatedAt, g.UpdatedAt)
		return err
	})
}

// groupCols reads a group with its member count and its ticket (D90).
const groupCols = `g.id, g.tenant_id, g.name, COALESCE(g.description, ''), COALESCE(g.owner, ''),
	g.created_at, g.updated_at,
	(SELECT COUNT(*) FROM finding_group_member m WHERE m.tenant_id = g.tenant_id AND m.group_id = g.id),
	g.application_id, g.ticket_status, g.ticket_attempts, COALESCE(g.ticket_error, ''), COALESCE(g.ticket_requested_by, ''),
	g.ticket_id, COALESCE(t.external_ref, ''), COALESCE(t.url, '')
	FROM finding_group g LEFT JOIN ticket t ON t.tenant_id = g.tenant_id AND t.id = g.ticket_id`

func scanGroup(row pgx.Row) (domain.FindingGroup, error) {
	var g domain.FindingGroup
	var status *string
	var tk domain.GroupTicket
	err := row.Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.Owner, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
		&g.ApplicationID, &status, &tk.Attempts, &tk.Error, &tk.RequestedBy, &tk.TicketID, &tk.ExternalRef, &tk.URL)
	if err == nil && status != nil {
		tk.Status = *status
		g.Ticket = &tk
	}
	return g, err
}

// GetFindingGroup fetches a finding group by ID with member count.
func (s *PostgresStore) GetFindingGroup(ctx context.Context, tenantID, id uuid.UUID) (*domain.FindingGroup, error) {
	var g domain.FindingGroup
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = scanGroup(tx.QueryRow(ctx, `SELECT `+groupCols+` WHERE g.tenant_id = $1 AND g.id = $2`, tenantID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ListFindingGroups lists all finding groups for a tenant.
func (s *PostgresStore) ListFindingGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.FindingGroup, error) {
	var groups []domain.FindingGroup
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+groupCols+` WHERE g.tenant_id = $1 ORDER BY g.created_at DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGroup(rows)
			if err != nil {
				return err
			}
			groups = append(groups, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// GroupMemberApplications returns the distinct applications of the group's findings.
func (s *PostgresStore) GroupMemberApplications(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT f.application_id FROM finding_group_member m
			JOIN finding f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			WHERE m.tenant_id = $1 AND m.group_id = $2`, tenantID, groupID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// RequestGroupTicket reserves the group's ticket; a reserved or done one is left as it is.
func (s *PostgresStore) RequestGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, requestedBy string) (bool, error) {
	var n int64
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE finding_group SET ticket_status = 'reserved', ticket_attempts = 0, ticket_next_at = NOW(),
				ticket_error = NULL, ticket_requested_by = $3, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2 AND (ticket_status IS NULL OR ticket_status = 'failed')`, tenantID, groupID, requestedBy)
		n = tag.RowsAffected()
		return err
	})
	return n > 0, err
}

// DeleteFindingGroup deletes a finding group and its memberships.
func (s *PostgresStore) DeleteFindingGroup(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM finding_group WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}

// AddGroupMembers adds findings to a group.
func (s *PostgresStore) AddGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	if len(findingIDs) == 0 {
		return nil
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `INSERT INTO finding_group_member (tenant_id, group_id, finding_id, added_at)
		          VALUES ($1, $2, $3, NOW())
		          ON CONFLICT (tenant_id, group_id, finding_id) DO NOTHING`
		for _, fid := range findingIDs {
			if _, err := tx.Exec(ctx, query, tenantID, groupID, fid); err != nil {
				return fmt.Errorf("adding member %s to group %s: %w", fid, groupID, err)
			}
		}
		return nil
	})
}

// RemoveGroupMembers removes findings from a group.
func (s *PostgresStore) RemoveGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	if len(findingIDs) == 0 {
		return nil
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `DELETE FROM finding_group_member WHERE tenant_id = $1 AND group_id = $2 AND finding_id = $3`
		for _, fid := range findingIDs {
			if _, err := tx.Exec(ctx, query, tenantID, groupID, fid); err != nil {
				return fmt.Errorf("removing member %s from group %s: %w", fid, groupID, err)
			}
		}
		return nil
	})
}

// ListGroupFindings returns all finding IDs in a group.
func (s *PostgresStore) ListGroupFindings(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error) {
	var findingIDs []uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT finding_id FROM finding_group_member WHERE tenant_id = $1 AND group_id = $2`
		rows, err := tx.Query(ctx, query, tenantID, groupID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var fid uuid.UUID
			if err := rows.Scan(&fid); err != nil {
				return err
			}
			findingIDs = append(findingIDs, fid)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return findingIDs, nil
}

// CreateSavedView creates a new saved search view.
func (s *PostgresStore) CreateSavedView(ctx context.Context, v *domain.SavedView) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	v.CreatedAt = time.Now()
	v.UpdatedAt = v.CreatedAt
	if v.Scope == "" {
		v.Scope = "tenant"
	}

	return s.withTenantTx(ctx, v.TenantID, func(tx pgx.Tx) error {
		query := `INSERT INTO saved_view (id, tenant_id, owner, name, query, sort, scope, created_at, updated_at)
		          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
		_, err := tx.Exec(ctx, query, v.ID, v.TenantID, v.Owner, v.Name, v.Query, v.Sort, v.Scope, v.CreatedAt, v.UpdatedAt)
		return err
	})
}

// GetSavedView retrieves a saved view by ID.
func (s *PostgresStore) GetSavedView(ctx context.Context, tenantID, id uuid.UUID) (*domain.SavedView, error) {
	var v domain.SavedView
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT id, tenant_id, owner, name, query, COALESCE(sort, ''), scope, created_at, updated_at
		          FROM saved_view
		          WHERE tenant_id = $1 AND id = $2`
		err := tx.QueryRow(ctx, query, tenantID, id).Scan(
			&v.ID, &v.TenantID, &v.Owner, &v.Name, &v.Query, &v.Sort, &v.Scope, &v.CreatedAt, &v.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ListSavedViews lists saved views visible to the user (tenant scope or user owner).
func (s *PostgresStore) ListSavedViews(ctx context.Context, tenantID uuid.UUID, owner string) ([]domain.SavedView, error) {
	var views []domain.SavedView
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT id, tenant_id, owner, name, query, COALESCE(sort, ''), scope, created_at, updated_at
		          FROM saved_view
		          WHERE tenant_id = $1 AND (scope = 'tenant' OR owner = $2)
		          ORDER BY created_at DESC`
		rows, err := tx.Query(ctx, query, tenantID, owner)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var v domain.SavedView
			if err := rows.Scan(&v.ID, &v.TenantID, &v.Owner, &v.Name, &v.Query, &v.Sort, &v.Scope, &v.CreatedAt, &v.UpdatedAt); err != nil {
				return err
			}
			views = append(views, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return views, nil
}

// DeleteSavedView deletes a saved view.
func (s *PostgresStore) DeleteSavedView(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM saved_view WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}
