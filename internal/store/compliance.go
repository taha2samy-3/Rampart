package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ControlMatch is what a control looks for in findings.
type ControlMatch struct {
	ID         string   `json:"id"`
	CWEs       []int    `json:"cwes"`
	Categories []string `json:"cats"`
}

// ScanEvidence is the last completed scan of one scanner family.
type ScanEvidence struct {
	Family string
	At     time.Time
}

// ComplianceReader answers the Compliance screen. Only the PostgreSQL store implements it (docs/16 D52).
type ComplianceReader interface {
	// ControlCounts returns, per control id, the open findings that bear on it by risk band. appID narrows to
	// one application.
	ControlCounts(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID, controls []ControlMatch) (map[string]map[string]int, error)
	// RecentScans returns each scanner family's last completed run since `since`.
	RecentScans(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID, since time.Time) ([]ScanEvidence, error)
}

func (s *PostgresStore) ControlCounts(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID, controls []ControlMatch) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	for _, c := range controls {
		out[c.ID] = map[string]int{}
	}
	body := make([]map[string]any, 0, len(controls))
	for _, c := range controls {
		cw, cats := c.CWEs, c.Categories
		if cw == nil {
			cw = []int{}
		}
		if cats == nil {
			cats = []string{}
		}
		body = append(body, map[string]any{"id": c.ID, "cwes": cw, "cats": cats})
	}
	raw, _ := json.Marshal(body)
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH c AS (SELECT * FROM jsonb_to_recordset($2::jsonb) AS x(id text, cwes int[], cats text[]))
			SELECT c.id, coalesce(f.risk_band, 'low'), count(*)
			FROM c JOIN finding f ON f.tenant_id = $1 AND f.state IN `+activeStates+`
			 AND ($3::uuid IS NULL OR f.application_id = $3)
			 AND ((cardinality(c.cwes) > 0 AND f.cwes && c.cwes) OR f.category = ANY(c.cats))
			GROUP BY c.id, coalesce(f.risk_band, 'low')`, tenantID, raw, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, band string
			var n int
			if err := rows.Scan(&id, &band, &n); err != nil {
				return err
			}
			out[id][band] += n
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) RecentScans(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID, since time.Time) ([]ScanEvidence, error) {
	var out []ScanEvidence
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT sc.scanner_family, max(r.created_at)
			FROM ingest_run_scope sc JOIN ingest_run r ON r.id = sc.ingest_run_id
			WHERE r.tenant_id = $1 AND r.status IN ('completed', 'completed_with_errors') AND r.created_at >= $2
			  AND ($3::uuid IS NULL OR r.application_id = $3)
			GROUP BY sc.scanner_family`, tenantID, since, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e ScanEvidence
			if err := rows.Scan(&e.Family, &e.At); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
