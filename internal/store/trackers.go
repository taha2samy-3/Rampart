package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"rampart/internal/domain"
)

var (
	_ domain.TrackerStore  = (*PostgresStore)(nil)
	_ domain.TrackerEvents = (*PostgresStore)(nil)
)

const maxTrackerEvents = 200

// ListTrackers lists all external tracker container definitions visible to a tenant (cluster + tenant-owned).
func (s *PostgresStore) ListTrackers(ctx context.Context, tenantID uuid.UUID) ([]domain.StoredTrackerObject, error) {
	var out []domain.StoredTrackerObject
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT 'cluster' AS origin, kind, '' AS namespace, name, COALESCE(applied_spec, spec),
			       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM cluster_policy WHERE kind = 'external_tracker'
			UNION ALL
			SELECT 'tenant', kind, namespace, name, COALESCE(applied_spec, spec),
			       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM policy_object WHERE tenant_id = $1 AND kind = 'external_tracker'
			ORDER BY 1, 2, 3, 4`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var obj domain.StoredTrackerObject
			if err := rows.Scan(&obj.Origin, &obj.Kind, &obj.Namespace, &obj.Name, &obj.Spec, &obj.Error, &obj.UpdatedAt); err != nil {
				return err
			}
			out = append(out, obj)
		}
		return rows.Err()
	})
	return out, err
}

// GetTracker looks up a specific ClusterExternalTracker or namespaced ExternalTracker visible to tenantID.
func (s *PostgresStore) GetTracker(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string) (domain.StoredTrackerObject, bool, error) {
	var obj domain.StoredTrackerObject
	var found bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if scope == "tenant" {
			err := tx.QueryRow(ctx, `
				SELECT 'tenant', kind, namespace, name, COALESCE(applied_spec, spec),
				       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
				  FROM policy_object
				 WHERE tenant_id = $1 AND kind = 'external_tracker' AND namespace = $2 AND name = $3`,
				tenantID, namespace, name).Scan(&obj.Origin, &obj.Kind, &obj.Namespace, &obj.Name, &obj.Spec, &obj.Error, &obj.UpdatedAt)
			if err == pgx.ErrNoRows {
				return nil
			}
			if err != nil {
				return err
			}
			found = true
			return nil
		}
		err := tx.QueryRow(ctx, `
			SELECT 'cluster', kind, '' AS namespace, name, COALESCE(applied_spec, spec),
			       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM cluster_policy
			 WHERE kind = 'external_tracker' AND name = $1`,
			name).Scan(&obj.Origin, &obj.Kind, &obj.Namespace, &obj.Name, &obj.Spec, &obj.Error, &obj.UpdatedAt)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return obj, found, err
}

// RecordTrackerEvent keeps a tracker event for the tenant that triggered it and retains only the newest 200 per tracker.
func (s *PostgresStore) RecordTrackerEvent(ctx context.Context, tenantID uuid.UUID, ev domain.TrackerEvent) error {
	detail := ev.Detail
	if detail == nil {
		detail = map[string]string{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if ev.ID == uuid.Nil {
		ev.ID = domain.NewID()
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO tracker_event (id, tenant_id, tracker_scope, tracker_namespace, tracker_name, event, outcome, message, detail, duration_ms, actor)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)`,
			ev.ID, tenantID, ev.Scope, ev.Namespace, ev.Name, ev.Event, ev.Outcome, ev.Message, raw, int(ev.Duration.Milliseconds()), ev.Actor); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM tracker_event
			 WHERE tenant_id = $1 AND tracker_scope = $2 AND tracker_namespace = $3 AND tracker_name = $4
			   AND id NOT IN (SELECT id FROM tracker_event
			                   WHERE tenant_id = $1 AND tracker_scope = $2 AND tracker_namespace = $3 AND tracker_name = $4
			                   ORDER BY created_at DESC, id DESC LIMIT $5)`,
			tenantID, ev.Scope, ev.Namespace, ev.Name, maxTrackerEvents)
		return err
	})
}

// ListTrackerEvents lists the tenant's events of one tracker container, newest first.
func (s *PostgresStore) ListTrackerEvents(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string, limit int) ([]domain.TrackerEvent, error) {
	if limit <= 0 || limit > maxTrackerEvents {
		limit = 50
	}
	var out []domain.TrackerEvent
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tracker_scope, tracker_namespace, tracker_name, event, outcome, message, detail, duration_ms, actor, created_at
			  FROM tracker_event
			 WHERE tenant_id = $1 AND tracker_scope = $2 AND tracker_namespace = $3 AND tracker_name = $4
			 ORDER BY created_at DESC, id DESC LIMIT $5`, tenantID, scope, namespace, name, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev domain.TrackerEvent
			var detail []byte
			var ms int
			if err := rows.Scan(&ev.ID, &ev.Scope, &ev.Namespace, &ev.Name, &ev.Event, &ev.Outcome, &ev.Message, &detail, &ms, &ev.Actor, &ev.CreatedAt); err != nil {
				return err
			}
			ev.Duration = durationMs(ms)
			_ = json.Unmarshal(detail, &ev.Detail)
			out = append(out, ev)
		}
		return rows.Err()
	})
	return out, err
}
