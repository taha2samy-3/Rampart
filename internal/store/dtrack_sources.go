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

// DTrackSource is a ScanSource that pulls from Dependency-Track (docs/16 D92).
type DTrackSource struct {
	TenantID          uuid.UUID
	ID                uuid.UUID
	Name              string
	Connector         string
	Spec              domain.DTrackSourceSpec
	Schedule          time.Duration
	LastPortfolioSync *time.Time
}

// DTrackDecision is the analysis Dependency-Track carries on a finding (docs/23 DT5).
type DTrackDecision struct {
	FindingID     uuid.UUID `json:"finding_id"`
	SourceID      uuid.UUID `json:"source_id"`
	State         string    `json:"state"`
	Justification string    `json:"justification,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	Applied       bool      `json:"applied"`
	SeenAt        time.Time `json:"seen_at"`
}

// DTrackSources is the store side of the wired Dependency-Track integration.
type DTrackSources interface {
	SaveDTrackSource(ctx context.Context, tenantID, sourceID uuid.UUID, connector string, spec json.RawMessage, schedule time.Duration) error
	GetDTrackSource(ctx context.Context, tenantID, sourceID uuid.UUID) (*DTrackSource, error)
	// ListDTrackSources reads across tenants: it needs rampart_system.
	ListDTrackSources(ctx context.Context) ([]DTrackSource, error)
	RecordPortfolioSync(ctx context.Context, tenantID, sourceID uuid.UUID, at time.Time, syncErr error) error
	// RecordDTrackDecision stores what DT says about a finding. It returns true when the decision is new or changed.
	RecordDTrackDecision(ctx context.Context, tenantID uuid.UUID, d DTrackDecision) (bool, error)
	ListDTrackDecisions(ctx context.Context, tenantID, sourceID uuid.UUID, pendingOnly bool) ([]DTrackDecision, error)
	FindAssetByDTrackUUID(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.Asset, error)
	FindAssetByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Asset, error)
}

func (s *PostgresStore) SaveDTrackSource(ctx context.Context, tenantID, sourceID uuid.UUID, connector string, spec json.RawMessage, schedule time.Duration) error {
	var conn *string
	if connector != "" {
		conn = &connector
	}
	var raw any
	if len(spec) > 0 {
		raw = []byte(spec)
	}
	secs := int(schedule / time.Second)
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scan_source SET connector = $3, dtrack_spec = $4, schedule_seconds = NULLIF($5, 0), type = CASE WHEN $3::text IS NULL THEN type ELSE 'apiPull' END
			WHERE tenant_id = $1 AND id = $2`, tenantID, sourceID, conn, raw, secs)
		return err
	})
}

const dtrackSourceCols = `tenant_id, id, name, connector, COALESCE(dtrack_spec, 'null'::jsonb), COALESCE(schedule_seconds, 0), last_portfolio_sync_at`

func scanDTrackSource(row pgx.Row) (DTrackSource, error) {
	var d DTrackSource
	var raw []byte
	var secs int
	if err := row.Scan(&d.TenantID, &d.ID, &d.Name, &d.Connector, &raw, &secs, &d.LastPortfolioSync); err != nil {
		return d, err
	}
	spec, err := domain.ParseDTrackSourceSpec(raw)
	if err != nil {
		return d, err
	}
	d.Spec = spec
	d.Schedule = time.Duration(secs) * time.Second
	if d.Schedule == 0 {
		d.Schedule = domain.DefaultDTrackSchedule
	}
	return d, nil
}

func (s *PostgresStore) GetDTrackSource(ctx context.Context, tenantID, sourceID uuid.UUID) (*DTrackSource, error) {
	var out DTrackSource
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanDTrackSource(tx.QueryRow(ctx, `SELECT `+dtrackSourceCols+` FROM scan_source
			WHERE tenant_id = $1 AND id = $2 AND connector IS NOT NULL AND disabled_at IS NULL`, tenantID, sourceID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PostgresStore) ListDTrackSources(ctx context.Context) ([]DTrackSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+dtrackSourceCols+` FROM scan_source WHERE connector IS NOT NULL AND disabled_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DTrackSource
	for rows.Next() {
		d, err := scanDTrackSource(rows)
		if err != nil {
			continue // a row whose spec no longer parses is skipped here and reported by the operator's condition
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RecordPortfolioSync(ctx context.Context, tenantID, sourceID uuid.UUID, at time.Time, syncErr error) error {
	var msg *string
	if syncErr != nil {
		m := syncErr.Error()
		msg = &m
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scan_source SET last_portfolio_sync_at = $3, last_portfolio_error = $4 WHERE tenant_id = $1 AND id = $2`,
			tenantID, sourceID, at, msg)
		return err
	})
}

func (s *PostgresStore) RecordDTrackDecision(ctx context.Context, tenantID uuid.UUID, d DTrackDecision) (bool, error) {
	var changed bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var oldState, oldJust string
		var oldApplied bool
		err := tx.QueryRow(ctx, `SELECT state, COALESCE(justification, ''), applied FROM dtrack_decision
			WHERE tenant_id = $1 AND finding_id = $2 FOR UPDATE`, tenantID, d.FindingID).Scan(&oldState, &oldJust, &oldApplied)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			changed = true
		case err != nil:
			return err
		default:
			changed = oldState != d.State || oldJust != d.Justification
		}
		applied := d.Applied || (!changed && oldApplied)
		_, err = tx.Exec(ctx, `INSERT INTO dtrack_decision (tenant_id, finding_id, source_id, state, justification, detail, applied, seen_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, NOW())
			ON CONFLICT (tenant_id, finding_id) DO UPDATE SET source_id = EXCLUDED.source_id, state = EXCLUDED.state,
				justification = EXCLUDED.justification, detail = EXCLUDED.detail, applied = EXCLUDED.applied, seen_at = NOW()`,
			tenantID, d.FindingID, d.SourceID, d.State, d.Justification, d.Detail, applied)
		return err
	})
	return changed, err
}

func (s *PostgresStore) ListDTrackDecisions(ctx context.Context, tenantID, sourceID uuid.UUID, pendingOnly bool) ([]DTrackDecision, error) {
	var out []DTrackDecision
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT finding_id, source_id, state, COALESCE(justification, ''), COALESCE(detail, ''), applied, seen_at
			FROM dtrack_decision WHERE tenant_id = $1 AND source_id = $2 AND (NOT $3 OR NOT applied) ORDER BY seen_at DESC LIMIT 1000`,
			tenantID, sourceID, pendingOnly)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DTrackDecision
			if err := rows.Scan(&d.FindingID, &d.SourceID, &d.State, &d.Justification, &d.Detail, &d.Applied, &d.SeenAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// FindAssetByDTrackUUID is mapping rule 3: a project a person mapped by hand keeps its application. It answers
// with the application only; the asset itself is keyed by project name (D10).
func (s *PostgresStore) FindAssetByDTrackUUID(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.Asset, error) {
	var app *uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT application_id FROM dtrack_project WHERE tenant_id = $1 AND project_uuid = $2
			AND mapping_rule = 'manual_ui_mapping' AND application_id IS NOT NULL`, tenantID, projectUUID).Scan(&app)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &domain.Asset{TenantID: tenantID, ApplicationID: app}, nil
}

// FindAssetByKey is mapping rule 4: an asset of any type whose key is the project's purl.
func (s *PostgresStore) FindAssetByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Asset, error) {
	var a domain.Asset
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, tenant_id, application_id FROM asset WHERE tenant_id = $1 AND key = $2 AND application_id IS NOT NULL LIMIT 1`,
			tenantID, key).Scan(&a.ID, &a.TenantID, &a.ApplicationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// DTrackSourceStatus is what the UI shows about one Dependency-Track source: real state, read from the tables.
type DTrackSourceStatus struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	Connector          string     `json:"connector"`
	ScheduleSeconds    int        `json:"schedule_seconds"`
	WebhookEnabled     bool       `json:"webhook_enabled"`
	TrustDecisions     bool       `json:"trust_upstream_decisions"`
	LastPortfolioSync  *time.Time `json:"last_portfolio_sync_at,omitempty"`
	LastPortfolioError string     `json:"last_portfolio_error,omitempty"`
	Projects           int        `json:"projects"`
	Unmapped           int        `json:"unmapped"`
	PendingDecisions   int        `json:"pending_decisions"`
	LastProjectError   string     `json:"last_project_error,omitempty"`
}

// ListTenantDTrackSources lists a tenant's Dependency-Track sources with their state.
func (s *PostgresStore) ListTenantDTrackSources(ctx context.Context, tenantID uuid.UUID) ([]DTrackSourceStatus, error) {
	var out []DTrackSourceStatus
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id, s.name, s.connector, COALESCE(s.schedule_seconds, $2),
				COALESCE((s.dtrack_spec->'webhook'->>'enabled')::boolean, false),
				COALESCE((s.dtrack_spec->'triageSync'->>'trustUpstreamDecisions')::boolean, false),
				s.last_portfolio_sync_at, COALESCE(s.last_portfolio_error, ''),
				(SELECT COUNT(*) FROM dtrack_project p WHERE p.tenant_id = s.tenant_id AND p.source_id = s.id),
				(SELECT COUNT(*) FROM dtrack_project p WHERE p.tenant_id = s.tenant_id AND p.source_id = s.id AND p.application_id IS NULL),
				(SELECT COUNT(*) FROM dtrack_decision d WHERE d.tenant_id = s.tenant_id AND d.source_id = s.id AND NOT d.applied),
				COALESCE((SELECT y.last_error FROM dtrack_sync y WHERE y.tenant_id = s.tenant_id AND y.source_id = s.id
					AND y.last_error IS NOT NULL AND y.last_error <> '' ORDER BY y.updated_at DESC LIMIT 1), '')
			FROM scan_source s WHERE s.tenant_id = $1 AND s.connector IS NOT NULL AND s.disabled_at IS NULL ORDER BY s.name`,
			tenantID, int(domain.DefaultDTrackSchedule/time.Second))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x DTrackSourceStatus
			if err := rows.Scan(&x.ID, &x.Name, &x.Connector, &x.ScheduleSeconds, &x.WebhookEnabled, &x.TrustDecisions,
				&x.LastPortfolioSync, &x.LastPortfolioError, &x.Projects, &x.Unmapped, &x.PendingDecisions, &x.LastProjectError); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// AppAsset is one asset of an application, for the merged SBOM.
type AppAsset struct {
	ID   uuid.UUID
	Name string
}

// ListApplicationAssets lists the assets attached to an application (D95).
func (s *PostgresStore) ListApplicationAssets(ctx context.Context, tenantID, appID uuid.UUID) ([]AppAsset, error) {
	var out []AppAsset
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, COALESCE(NULLIF(display_name, ''), key) FROM asset WHERE tenant_id = $1 AND application_id = $2 ORDER BY key`, tenantID, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AppAsset
			if err := rows.Scan(&a.ID, &a.Name); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
