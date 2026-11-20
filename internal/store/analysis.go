package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"rampart/internal/analyzer/matcher"
	"rampart/internal/domain"
)

var (
	_ domain.AnalysisStore  = (*PostgresStore)(nil)
	_ matcher.AdvisoryStore = (*PostgresStore)(nil)
)

// GetSBOMByID returns one SBOM and its components.
func (s *PostgresStore) GetSBOMByID(ctx context.Context, tenantID, sbomID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error) {
	var (
		sbom       domain.SBOM
		components []domain.SBOMComponent
	)
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var depsJSON []byte
		err := tx.QueryRow(ctx, `
			SELECT id, tenant_id, asset_id, ingest_run_id, format, spec_version, serial, coalesce(object_ref, ''),
			       coalesce(root_component, ''), component_count, dependencies, created_at, track
			  FROM sbom WHERE tenant_id = $1 AND id = $2`, tenantID, sbomID).Scan(
			&sbom.ID, &sbom.TenantID, &sbom.AssetID, &sbom.IngestRunID, &sbom.Format, &sbom.SpecVersion,
			&sbom.Serial, &sbom.ObjectRef, &sbom.RootComponent, &sbom.ComponentCount, &depsJSON, &sbom.CreatedAt, &sbom.Track)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if len(depsJSON) > 0 {
			_ = json.Unmarshal(depsJSON, &sbom.Dependencies)
		}
		rows, err := tx.Query(ctx, `
			SELECT ref, purl, purl_base, name, version, licenses, coalesce(scope, ''), direct, hashes
			  FROM sbom_component WHERE tenant_id = $1 AND sbom_id = $2`, tenantID, sbomID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c          domain.SBOMComponent
				hashesJSON []byte
			)
			c.TenantID, c.SBOMID = tenantID, sbomID
			if err := rows.Scan(&c.Ref, &c.Purl, &c.PurlBase, &c.Name, &c.Version, &c.Licenses, &c.Scope, &c.Direct, &hashesJSON); err != nil {
				return err
			}
			if len(hashesJSON) > 0 {
				_ = json.Unmarshal(hashesJSON, &c.Hashes)
			}
			components = append(components, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	return &sbom, components, nil
}

// LatestSBOMs returns the newest SBOM of every asset and track, or of one asset.
func (s *PostgresStore) LatestSBOMs(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID) ([]domain.SBOM, error) {
	var out []domain.SBOM
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (asset_id, track) id, tenant_id, asset_id, ingest_run_id, format, component_count, created_at, track
			  FROM sbom WHERE tenant_id = $1 AND ($2::uuid IS NULL OR asset_id = $2)
			 ORDER BY asset_id, track, created_at DESC, id`, tenantID, assetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b domain.SBOM
			if err := rows.Scan(&b.ID, &b.TenantID, &b.AssetID, &b.IngestRunID, &b.Format, &b.ComponentCount, &b.CreatedAt, &b.Track); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// ClaimSBOMAnalysis records a pending analysis. It does nothing, and says so, when one is pending or running for the same SBOM
// and analyzer and is younger than staleAfter: a crash that left a row behind frees it after that time.
func (s *PostgresStore) ClaimSBOMAnalysis(ctx context.Context, a domain.SBOMAnalysis, staleAfter time.Duration) (bool, error) {
	claimed := false
	err := s.withTenantTx(ctx, a.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO sbom_analysis (tenant_id, sbom_id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name, state, trigger)
			VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
			ON CONFLICT (tenant_id, sbom_id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name) DO UPDATE
			   SET state = 'pending', trigger = EXCLUDED.trigger, attempts = 0, error = '', components = 0, findings = 0, created = 0, closed = 0,
			       started_at = NULL, finished_at = NULL, created_at = NOW(), updated_at = NOW()
			 WHERE sbom_analysis.state NOT IN ('pending', 'running')
			    OR sbom_analysis.updated_at < NOW() - make_interval(secs => $8)`,
			a.TenantID, a.SBOMID, a.Analyzer.Kind, a.Analyzer.Scope, a.Analyzer.Namespace, a.Analyzer.Name, string(a.Trigger), staleAfter.Seconds())
		if err != nil {
			return err
		}
		claimed = tag.RowsAffected() == 1
		return nil
	})
	return claimed, err
}

// SaveSBOMAnalysis writes the state of a claimed analysis.
func (s *PostgresStore) SaveSBOMAnalysis(ctx context.Context, a domain.SBOMAnalysis) error {
	return s.withTenantTx(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE sbom_analysis
			   SET state = $7, attempts = $8, error = $9, components = $10, findings = $11, created = $12, closed = $13,
			       started_at = $14, finished_at = $15, updated_at = NOW()
			 WHERE tenant_id = $1 AND sbom_id = $2 AND analyzer_kind = $3 AND analyzer_scope = $4 AND analyzer_namespace = $5 AND analyzer_name = $6`,
			a.TenantID, a.SBOMID, a.Analyzer.Kind, a.Analyzer.Scope, a.Analyzer.Namespace, a.Analyzer.Name,
			string(a.State), a.Attempts, a.Error, a.Components, a.Findings, a.Created, a.Closed, a.StartedAt, a.FinishedAt)
		return err
	})
}

// GetSBOMAnalysis returns the record of an analysis, or ErrNotFound.
func (s *PostgresStore) GetSBOMAnalysis(ctx context.Context, tenantID, sbomID uuid.UUID, ref domain.AnalyzerRef) (*domain.SBOMAnalysis, error) {
	var a domain.SBOMAnalysis
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var state, trigger string
		err := tx.QueryRow(ctx, `
			SELECT state, trigger, attempts, error, components, findings, created, closed, started_at, finished_at, created_at, updated_at
			  FROM sbom_analysis
			 WHERE tenant_id = $1 AND sbom_id = $2 AND analyzer_kind = $3 AND analyzer_scope = $4 AND analyzer_namespace = $5 AND analyzer_name = $6`,
			tenantID, sbomID, ref.Kind, ref.Scope, ref.Namespace, ref.Name).Scan(
			&state, &trigger, &a.Attempts, &a.Error, &a.Components, &a.Findings, &a.Created, &a.Closed, &a.StartedAt, &a.FinishedAt, &a.CreatedAt, &a.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		a.State, a.Trigger = domain.AnalysisState(state), domain.AnalysisTrigger(trigger)
		return err
	})
	if err != nil {
		return nil, err
	}
	a.TenantID, a.SBOMID, a.Analyzer = tenantID, sbomID, ref
	return &a, nil
}

// ListSBOMAnalyses returns the records of all analyses for one SBOM.
func (s *PostgresStore) ListSBOMAnalyses(ctx context.Context, tenantID, sbomID uuid.UUID) ([]domain.SBOMAnalysis, error) {
	var out []domain.SBOMAnalysis
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name,
			       state, trigger, attempts, error, components, findings, created, closed,
			       started_at, finished_at, created_at, updated_at
			  FROM sbom_analysis
			 WHERE tenant_id = $1 AND sbom_id = $2
			 ORDER BY analyzer_name ASC`, tenantID, sbomID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				a              domain.SBOMAnalysis
				state, trigger string
			)
			a.TenantID, a.SBOMID = tenantID, sbomID
			if err := rows.Scan(&a.Analyzer.Kind, &a.Analyzer.Scope, &a.Analyzer.Namespace, &a.Analyzer.Name,
				&state, &trigger, &a.Attempts, &a.Error, &a.Components, &a.Findings, &a.Created, &a.Closed,
				&a.StartedAt, &a.FinishedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
				return err
			}
			a.State, a.Trigger = domain.AnalysisState(state), domain.AnalysisTrigger(trigger)
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ListDueSBOMs returns the newest SBOMs this analyzer has not analysed since the cutoffs, those it never analysed first, then the
// oldest analysis. An analysis in flight is not due.
func (s *PostgresStore) ListDueSBOMs(ctx context.Context, tenantID uuid.UUID, ref domain.AnalyzerRef, completedBefore, failedBefore time.Time, limit int) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH latest AS (
			    SELECT DISTINCT ON (asset_id, track) id FROM sbom WHERE tenant_id = $1 ORDER BY asset_id, track, created_at DESC, id
			)
			SELECT l.id
			  FROM latest l
			  LEFT JOIN sbom_analysis a ON a.tenant_id = $1 AND a.sbom_id = l.id
			       AND a.analyzer_kind = $2 AND a.analyzer_scope = $3 AND a.analyzer_namespace = $4 AND a.analyzer_name = $5
			 WHERE a.sbom_id IS NULL
			    OR (a.state IN ('completed', 'cancelled', 'not_applicable') AND COALESCE(a.finished_at, a.updated_at) < $6)
			    OR (a.state IN ('failed', 'timed_out') AND COALESCE(a.finished_at, a.updated_at) < $7)
			 ORDER BY COALESCE(a.finished_at, a.updated_at, 'epoch'::timestamptz), l.id
			 LIMIT $8`,
			tenantID, ref.Kind, ref.Scope, ref.Namespace, ref.Name, completedBefore, failedBefore, limit)
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

// CountAnalysesInFlight counts the analyses pending or running in every tenant. It reads across tenants, so it needs the system role.
func (s *PostgresStore) CountAnalysesInFlight(ctx context.Context, staleAfter time.Duration) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM sbom_analysis
		 WHERE state IN ('pending', 'running') AND updated_at >= NOW() - make_interval(secs => $1)`, staleAfter.Seconds()).Scan(&n)
	return n, err
}

// FindCandidatesByPurlBase returns the advisories that name any of the package URLs (without version), from the affected ranges the OSV
// feed loaded. A range with no "introduced" starts at the first version; one with neither "fixed" nor a limit has no end. A withdrawn
// advisory is left out. A row of range type VERSIONS lists the exact versions that are affected. The vulnerability table has a CVSS
// score but no severity word, so the matcher takes the severity from the score.
func (s *PostgresStore) FindCandidatesByPurlBase(ctx context.Context, purlBases []string) ([]matcher.Advisory, error) {
	if len(purlBases) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT va.vulnerability_id, va.source_id, va.ecosystem, va.package_name, va.purl_base, va.range_type,
		       coalesce(va.introduced, ''), coalesce(va.fixed, ''), coalesce(va.last_affected, ''), va.versions,
		       coalesce(v.summary, ''), coalesce(v.description, ''), coalesce(v.cvss_best_score, 0)::float8, coalesce(v.cvss_best_vector, '')
		  FROM vulnerability_affected va
		  LEFT JOIN vulnerability v ON v.id = va.vulnerability_id
		 WHERE va.purl_base = ANY($1) AND va.withdrawn IS NULL AND va.range_type IN ('SEMVER', 'ECOSYSTEM', 'VERSIONS')`, purlBases)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []matcher.Advisory
	for rows.Next() {
		var (
			a                      matcher.Advisory
			sourceID, lastAffected string
			versions               []string
			purl                   *string
		)
		if err := rows.Scan(&a.ID, &sourceID, &a.Ecosystem, &a.PackageName, &purl, &a.RangeType, &a.Introduced, &a.Fixed, &lastAffected, &versions,
			&a.Summary, &a.Description, &a.CVSSScore, &a.CVSSVector); err != nil {
			return nil, err
		}
		if purl != nil {
			a.PurlBase = *purl
		}
		if sourceID != "" && sourceID != a.ID {
			a.Aliases = []string{sourceID}
		}
		a.LastAffected, a.Versions = lastAffected, versions
		out = append(out, a)
	}
	return out, rows.Err()
}

var _ domain.ParserRunStore = (*PostgresStore)(nil)

// LastRunByParser returns, for each parser that has read something for the tenant, its last run and the last time it completed. The analyses an
// analyzer merges are not a parser's work and are left out.
func (s *PostgresStore) LastRunByParser(ctx context.Context, tenantID uuid.UUID) (map[string]domain.ParserLastRun, error) {
	out := map[string]domain.ParserLastRun{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT format,
			       (array_agg(id ORDER BY created_at DESC))[1],
			       (array_agg(status ORDER BY created_at DESC))[1],
			       (array_agg(coalesce(error, '') ORDER BY created_at DESC))[1],
			       max(created_at),
			       max(created_at) FILTER (WHERE status IN ('completed', 'completed_with_errors'))
			  FROM ingest_run WHERE tenant_id = $1 AND format <> 'sbom-analysis' GROUP BY format`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				format, status, errText string
				id                      uuid.UUID
				at                      time.Time
				ok                      *time.Time
			)
			if err := rows.Scan(&format, &id, &status, &errText, &at, &ok); err != nil {
				return err
			}
			out[format] = domain.ParserLastRun{RunID: id, Status: domain.IngestRunStatus(status), Error: errText, At: at, LastSuccess: ok}
		}
		return rows.Err()
	})
	return out, err
}
