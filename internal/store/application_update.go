package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"rampart/internal/domain"
)

// ErrManagedByResource is a change of an application that an Application resource owns: the resource is the truth for
// its context (D55), so a change made elsewhere would be undone by the next reconcile.
var ErrManagedByResource = errors.New("the application is managed by an Application resource")

// ApplicationContextWriter changes what the score knows about an application. Only the PostgreSQL store implements it.
type ApplicationContextWriter interface {
	UpdateApplicationContext(ctx context.Context, tenantID, appID uuid.UUID, u domain.ApplicationContextUpdate) (*domain.Application, error)
}

// UpdateApplicationContext applies an update made by a person. An application an Application resource manages is refused
// (ErrManagedByResource); one that ingest made, or that a resource let go, is changed, and stays free for a resource to
// adopt later. When the change moves the score (criticality, exposure, data, controls) the application is flagged and the
// sweep re-scores its findings, as for a resource (D40, D55).
func (s *PostgresStore) UpdateApplicationContext(ctx context.Context, tenantID, appID uuid.UUID, u domain.ApplicationContextUpdate) (*domain.Application, error) {
	var out *domain.Application
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var prev domain.Application
		var managedBy string
		err := tx.QueryRow(ctx, `SELECT managed_by, business_criticality, internet_facing, data_classification, compensating_controls, lifecycle, type, environment
			FROM application WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, appID).
			Scan(&managedBy, &prev.BusinessCriticality, &prev.InternetFacing, &prev.DataClassification, &prev.CompensatingControls, &prev.Lifecycle, &prev.Type, &prev.Environment)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if managedBy == "crd" {
			return ErrManagedByResource
		}
		next := u.Apply(prev)
		if _, err := tx.Exec(ctx, `UPDATE application SET business_criticality = $3, internet_facing = $4, data_classification = $5,
			compensating_controls = $6, lifecycle = $7, environment = $8, version = version + 1 WHERE tenant_id = $1 AND id = $2`,
			tenantID, appID, next.BusinessCriticality, next.InternetFacing, nonNil(next.DataClassification), nonNil(next.CompensatingControls), next.Lifecycle, next.Environment); err != nil {
			return err
		}
		if domain.ScoreContextChanged(prev, next) {
			if _, err := tx.Exec(ctx, `UPDATE application SET rescore_needed = TRUE WHERE tenant_id = $1 AND id = $2`, tenantID, appID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: updating the context of an application: %w", err)
	}
	out, err = s.GetApplication(ctx, tenantID, appID)
	return out, err
}
