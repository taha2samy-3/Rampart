package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"rampart/internal/domain"
)

var (
	_ domain.AnalyzerStore  = (*PostgresStore)(nil)
	_ domain.AnalyzerEvents = (*PostgresStore)(nil)
)

// maxAnalyzerEvents is how many events of one analyzer are kept: the newest.
const maxAnalyzerEvents = 200

// ListAnalyzers lists the analyzers a tenant sees: the cluster's, and the tenant's own. An analyzer whose first spec was refused has no spec in
// force; its refused spec is returned with the reason, so the screen can show it and say why.
func (s *PostgresStore) ListAnalyzers(ctx context.Context, tenantID uuid.UUID) ([]domain.StoredAnalyzerObject, error) {
	var out []domain.StoredAnalyzerObject
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT 'cluster' AS origin, kind, '' AS namespace, name, COALESCE(applied_spec, spec),
			       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM cluster_policy WHERE kind IN ('external_analyzer', 'sbom_analyzer')
			UNION ALL
			SELECT 'tenant', kind, namespace, name, COALESCE(applied_spec, spec),
			       CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM policy_object WHERE tenant_id = $1 AND kind IN ('external_analyzer', 'sbom_analyzer')
			ORDER BY 1, 2, 3, 4`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a domain.StoredAnalyzerObject
			if err := rows.Scan(&a.Origin, &a.Kind, &a.Namespace, &a.Name, &a.Spec, &a.Error, &a.UpdatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// RecordAnalyzerEvent keeps an event of an analyzer for the tenant that caused it, and drops the oldest beyond the newest 200 of that analyzer.
func (s *PostgresStore) RecordAnalyzerEvent(ctx context.Context, tenantID uuid.UUID, ev domain.AnalyzerEvent) error {
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
			INSERT INTO analyzer_event (id, tenant_id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name, event, outcome, message, detail, duration_ms, actor)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)`,
			ev.ID, tenantID, ev.Kind, ev.Scope, ev.Namespace, ev.Name, ev.Event, ev.Outcome, ev.Message, raw, int(ev.Duration.Milliseconds()), ev.Actor); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM analyzer_event
			 WHERE tenant_id = $1 AND analyzer_kind = $2 AND analyzer_scope = $3 AND analyzer_namespace = $4 AND analyzer_name = $5
			   AND id NOT IN (SELECT id FROM analyzer_event
			                   WHERE tenant_id = $1 AND analyzer_kind = $2 AND analyzer_scope = $3 AND analyzer_namespace = $4 AND analyzer_name = $5
			                   ORDER BY created_at DESC, id DESC LIMIT $6)`,
			tenantID, ev.Kind, ev.Scope, ev.Namespace, ev.Name, maxAnalyzerEvents)
		return err
	})
}

// ListAnalyzerEvents lists the tenant's events of one analyzer, newest first.
func (s *PostgresStore) ListAnalyzerEvents(ctx context.Context, tenantID uuid.UUID, kind, scope, namespace, name string, limit int) ([]domain.AnalyzerEvent, error) {
	if limit <= 0 || limit > maxAnalyzerEvents {
		limit = 50
	}
	var out []domain.AnalyzerEvent
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name, event, outcome, message, detail, duration_ms, actor, created_at
			  FROM analyzer_event
			 WHERE tenant_id = $1 AND analyzer_kind = $2 AND analyzer_scope = $3 AND analyzer_namespace = $4 AND analyzer_name = $5
			 ORDER BY created_at DESC, id DESC LIMIT $6`, tenantID, kind, scope, namespace, name, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev domain.AnalyzerEvent
			var detail []byte
			var ms int
			if err := rows.Scan(&ev.ID, &ev.Kind, &ev.Scope, &ev.Namespace, &ev.Name, &ev.Event, &ev.Outcome, &ev.Message, &detail, &ms, &ev.Actor, &ev.CreatedAt); err != nil {
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

func durationMs(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

var _ domain.AdvisorySummarizer = (*PostgresStore)(nil)

// AdvisorySummary counts the affected ranges the matcher can match against, by ecosystem, leaving out advisories their source withdrew. The table is
// global (no tenant's data), so the question is the same for everyone.
func (s *PostgresStore) AdvisorySummary(ctx context.Context) (domain.AdvisorySummary, error) {
	var sum domain.AdvisorySummary
	rows, err := s.pool.Query(ctx, `SELECT ecosystem, count(*) FROM vulnerability_affected WHERE withdrawn IS NULL GROUP BY ecosystem ORDER BY count(*) DESC, ecosystem LIMIT 100`)
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	for rows.Next() {
		var e domain.EcosystemAdvisory
		if err := rows.Scan(&e.Ecosystem, &e.Ranges); err != nil {
			return sum, err
		}
		sum.Ranges += e.Ranges
		sum.Ecosystems = append(sum.Ecosystems, e)
	}
	return sum, rows.Err()
}
