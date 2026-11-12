package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// Aggregator answers the questions of the Overview and Applications screens. PostgreSQL computes them from the
// finding table (docs/16 D43); the read models of docs/12 (application_summary, trend_daily) are not built yet.
type Aggregator interface {
	ApplicationSummaries(ctx context.Context, tenantID uuid.UUID) ([]domain.AppSummary, error)
	ApplicationDetail(ctx context.Context, tenantID, appID uuid.UUID) (*domain.AppDetail, error)
	Overview(ctx context.Context, tenantID uuid.UUID, since time.Time) (*domain.Overview, error)
	Trend(ctx context.Context, tenantID uuid.UUID, days int) ([]domain.TrendPoint, error)
}

const activeStates = `('open', 'under_investigation', 'affected')`

func emptyBands() map[string]int {
	m := map[string]int{}
	for _, b := range domain.Bands {
		m[b] = 0
	}
	return m
}

const summaryCols = `a.id, a.slug, a.name, a.business_criticality, a.internet_facing,
	count(f.id) FILTER (WHERE f.risk_band = 'critical'), count(f.id) FILTER (WHERE f.risk_band = 'high'),
	count(f.id) FILTER (WHERE f.risk_band = 'medium'), count(f.id) FILTER (WHERE f.risk_band = 'low'),
	coalesce(max(f.risk_score), 0), count(f.id) FILTER (WHERE f.sla_breached_at IS NOT NULL),
	(SELECT max(r.created_at) FROM ingest_run r WHERE r.tenant_id = a.tenant_id AND r.application_id = a.id AND r.status IN ('completed', 'completed_with_errors'))`

func scanSummary(row pgx.Row) (domain.AppSummary, error) {
	s := domain.AppSummary{Open: emptyBands()}
	var c, h, m, l int
	if err := row.Scan(&s.ID, &s.Slug, &s.Name, &s.Criticality, &s.InternetFacing, &c, &h, &m, &l, &s.RiskScore, &s.SLABreached, &s.LastScan); err != nil {
		return s, err
	}
	s.Open["critical"], s.Open["high"], s.Open["medium"], s.Open["low"] = c, h, m, l
	s.Exposure = c + h
	return s, nil
}

// ApplicationSummaries lists every application of the tenant, the riskiest first, including those with no findings.
func (s *PostgresStore) ApplicationSummaries(ctx context.Context, tenantID uuid.UUID) ([]domain.AppSummary, error) {
	var out []domain.AppSummary
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+summaryCols+`
			FROM application a
			LEFT JOIN finding f ON f.tenant_id = a.tenant_id AND f.application_id = a.id AND f.state IN `+activeStates+`
			WHERE a.tenant_id = $1
			GROUP BY a.id
			ORDER BY coalesce(max(f.risk_score), 0) DESC, a.name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sum, err := scanSummary(rows)
			if err != nil {
				return err
			}
			out = append(out, sum)
		}
		return rows.Err()
	})
	return out, err
}

func slaStanding(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, appID *uuid.UUID) (domain.SLAStanding, error) {
	var st domain.SLAStanding
	err := tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE resolution = 'fixed' AND resolved_at IS NOT NULL AND resolved_at <= sla_due_date),
		       count(*) FILTER (WHERE resolution = 'fixed' AND resolved_at IS NOT NULL AND resolved_at > sla_due_date),
		       count(*) FILTER (WHERE state IN `+activeStates+` AND sla_breached_at IS NOT NULL)
		FROM finding
		WHERE tenant_id = $1 AND ($2::uuid IS NULL OR application_id = $2) AND sla_due_date IS NOT NULL
		  AND (resolved_at >= now() - interval '90 days' OR (state IN `+activeStates+` AND sla_breached_at IS NOT NULL))`,
		tenantID, appID).Scan(&st.Within, &st.Late, &st.Breached)
	if err != nil {
		return st, err
	}
	if total := st.Within + st.Late + st.Breached; total > 0 {
		a := float64(st.Within) / float64(total)
		st.Adherence = &a
	}
	return st, nil
}

// ApplicationDetail is the summary of an application with its SLA standing, MTTR and coverage.
func (s *PostgresStore) ApplicationDetail(ctx context.Context, tenantID, appID uuid.UUID) (*domain.AppDetail, error) {
	var d *domain.AppDetail
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		sum, err := scanSummary(tx.QueryRow(ctx, `SELECT `+summaryCols+`
			FROM application a
			LEFT JOIN finding f ON f.tenant_id = a.tenant_id AND f.application_id = a.id AND f.state IN `+activeStates+`
			WHERE a.tenant_id = $1 AND a.id = $2 GROUP BY a.id`, tenantID, appID))
		if err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		d = &domain.AppDetail{AppSummary: sum, MTTR: []domain.MTTR{}, Coverage: []domain.CoverageRow{}}
		if d.SLA, err = slaStanding(ctx, tx, tenantID, &appID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT risk_band, avg(extract(epoch FROM (resolved_at - first_seen)) / 86400)::float8, count(*)
			FROM finding WHERE tenant_id = $1 AND application_id = $2 AND resolution = 'fixed' AND resolved_at >= now() - interval '90 days'
			GROUP BY risk_band`, tenantID, appID)
		if err != nil {
			return err
		}
		byBand := map[string]domain.MTTR{}
		for rows.Next() {
			var m domain.MTTR
			if err := rows.Scan(&m.Band, &m.Days, &m.Fixed); err != nil {
				rows.Close()
				return err
			}
			byBand[m.Band] = m
		}
		rows.Close()
		for _, b := range domain.Bands { // worst first, only the bands that had a fix
			if m, ok := byBand[b]; ok {
				d.MTTR = append(d.MTTR, m)
			}
		}
		cov, err := tx.Query(ctx, `SELECT sc.asset_id, a.key, sc.scanner_family, max(r.created_at)
			FROM ingest_run_scope sc
			JOIN ingest_run r ON r.id = sc.ingest_run_id AND r.tenant_id = sc.tenant_id
			JOIN asset a ON a.id = sc.asset_id AND a.tenant_id = sc.tenant_id
			WHERE sc.tenant_id = $1 AND r.application_id = $2 AND r.status IN ('completed', 'completed_with_errors')
			GROUP BY sc.asset_id, a.key, sc.scanner_family ORDER BY a.key, sc.scanner_family`, tenantID, appID)
		if err != nil {
			return err
		}
		defer cov.Close()
		for cov.Next() {
			var c domain.CoverageRow
			if err := cov.Scan(&c.AssetID, &c.Asset, &c.Scanner, &c.LastScan); err != nil {
				return err
			}
			d.Coverage = append(d.Coverage, c)
		}
		return cov.Err()
	})
	return d, err
}

// Overview computes the opening screen for a tenant. since is the start of "what changed" (usually 24 hours ago).
func (s *PostgresStore) Overview(ctx context.Context, tenantID uuid.UUID, since time.Time) (*domain.Overview, error) {
	o := &domain.Overview{Open: emptyBands(), Overdue: []domain.OverdueFinding{}, TopApps: []domain.AppSummary{}, Gaps: []domain.AppSummary{}}
	o.Changes.Since = since
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT risk_band, count(*) FROM finding WHERE tenant_id = $1 AND state IN `+activeStates+` GROUP BY risk_band`, tenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var b string
			var n int
			if err := rows.Scan(&b, &n); err != nil {
				rows.Close()
				return err
			}
			o.Open[b] = n
		}
		rows.Close()
		if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM finding WHERE tenant_id = $1 AND first_seen >= $2),
			(SELECT count(DISTINCT finding_id) FROM finding_event WHERE tenant_id = $1 AND type = 'reactivated' AND at >= $2),
			(SELECT count(*) FROM finding WHERE tenant_id = $1 AND resolution = 'fixed' AND resolved_at >= $2)`, tenantID, since).
			Scan(&o.Changes.New, &o.Changes.Reopened, &o.Changes.Fixed); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM finding WHERE tenant_id = $1 AND state IN `+activeStates+`
			AND sla_due_date < now() AND sla_paused_at IS NULL`, tenantID).Scan(&o.OverdueTotal); err != nil {
			return err
		}
		od, err := tx.Query(ctx, `SELECT f.id, f.title, f.risk_band, f.severity, f.sla_due_date, a.slug, a.name
			FROM finding f JOIN application a ON a.id = f.application_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.state IN `+activeStates+` AND f.sla_due_date < now() AND f.sla_paused_at IS NULL
			ORDER BY f.sla_due_date ASC, f.risk_score DESC LIMIT 10`, tenantID)
		if err != nil {
			return err
		}
		for od.Next() {
			var f domain.OverdueFinding
			if err := od.Scan(&f.ID, &f.Title, &f.Band, &f.Severity, &f.Due, &f.AppSlug, &f.AppName); err != nil {
				od.Close()
				return err
			}
			o.Overdue = append(o.Overdue, f)
		}
		od.Close()
		o.SLA, err = slaStanding(ctx, tx, tenantID, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	apps, err := s.ApplicationSummaries(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	stale := time.Now().Add(-14 * 24 * time.Hour)
	for _, a := range apps {
		if a.Exposure > 0 || a.RiskScore > 0 {
			if len(o.TopApps) < 5 {
				o.TopApps = append(o.TopApps, a)
			}
		}
		if a.LastScan == nil || a.LastScan.Before(stale) {
			o.Gaps = append(o.Gaps, a)
		}
	}
	return o, nil
}

// Trend is the inventory at the end of each of the last days days: how many findings were active, how many were first
// seen that day and how many were fixed. It is computed from the finding table; trend_daily (docs/12) is the planned
// read model for tenants where this gets slow.
func (s *PostgresStore) Trend(ctx context.Context, tenantID uuid.UUID, days int) ([]domain.TrendPoint, error) {
	days = max(1, min(days, 180))
	var out []domain.TrendPoint
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH days AS (
				SELECT generate_series(date_trunc('day', now()) - ($2::int - 1) * interval '1 day', date_trunc('day', now()), interval '1 day') AS d
			)
			SELECT d.d,
			  (SELECT count(*) FROM finding f WHERE f.tenant_id = $1 AND f.first_seen < d.d + interval '1 day'
			     AND (f.resolved_at IS NULL OR f.resolved_at >= d.d + interval '1 day')),
			  (SELECT count(*) FROM finding f WHERE f.tenant_id = $1 AND f.first_seen >= d.d AND f.first_seen < d.d + interval '1 day'),
			  (SELECT count(*) FROM finding f WHERE f.tenant_id = $1 AND f.resolution = 'fixed' AND f.resolved_at >= d.d AND f.resolved_at < d.d + interval '1 day')
			FROM days d ORDER BY d.d`, tenantID, days)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.TrendPoint
			if err := rows.Scan(&p.Day, &p.Open, &p.New, &p.Closed); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
