package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

var (
	ErrNotFound = errors.New("store: record not found")
)

// PostgresStore implements store.Store on PostgreSQL 16+ with Row-Level Security (D4).
type PostgresStore struct {
	pool *pgxpool.Pool
	// tx is set only on the store handed to InTenantTx callbacks: every method
	// then runs inside that one transaction instead of opening its own (D13).
	tx       pgx.Tx
	txTenant uuid.UUID
}

// ErrCrossTenantTx is returned when a tenant-scoped transaction is asked to touch another tenant.
var ErrCrossTenantTx = errors.New("store: operation targets a different tenant than the open transaction")

// NewPostgresStore creates a PostgresStore backed by an existing pgx connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// ConnectPostgres establishes a pooled connection to PostgreSQL using pgx.
func ConnectPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: failed to parse database connection URL: %w", err)
	}
	// D4: the pooled URL goes through PgBouncer in transaction mode, where
	// cached server-side prepared statements break across connections.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	cfg.MaxConns = 25
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: failed to create pgx pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: failed to ping database: %w", err)
	}

	return NewPostgresStore(pool), nil
}

// Close closes the underlying pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Ping checks whether the PostgreSQL database connection is alive.
func (s *PostgresStore) Ping(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("store: database pool is not connected")
	}
	return s.pool.Ping(ctx)
}

// Pool returns the underlying pgx pool.
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// AutoMigrate applies migrations against the database URL (D4, D6).
func AutoMigrate(ctx context.Context, dbURL string) error {
	return MigrateUp(ctx, dbURL)
}

// withTenantTx executes a transaction with 'app.tenant_id' set locally (normative D4).
func (s *PostgresStore) withTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(tx pgx.Tx) error) error {
	if tenantID == domain.NilID {
		return domain.ErrInvalidTenantID
	}

	if s.tx != nil { // already inside InTenantTx
		if tenantID != s.txTenant {
			return ErrCrossTenantTx
		}
		return fn(s.tx)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// D4: select set_config('app.tenant_id', $1, true)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("store: failed to set app.tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// findingCols is the single column list for reading a finding; every reader that
// may be followed by an upsert must load all mutable columns, otherwise the
// upsert would overwrite them with zero values.
const findingCols = `id, tenant_id, finding_key, dedup_scope, asset_id, application_id, track,
	category, rule_scanner_family, rule_id, title, coalesce(description, ''),
	cwes, vulnerability_id, location, severity, tool_severity,
	coalesce(severity_override_reason, ''), coalesce(cvss_vector, ''),
	risk_score, state, coalesce(previous_state, ''), coalesce(state_reason, ''),
	detection, content_hash, weak_fingerprint, first_seen, last_seen,
	resolved_at, coalesce(resolution, ''), reopened_count, occurrence_count, version, created_at, updated_at`

func scanFinding(row pgx.Row) (*domain.Finding, error) {
	var (
		f                                                      domain.Finding
		locationJSON                                           []byte
		category, severity, state, prevState, detection, overr string
		resolution                                             string
	)
	err := row.Scan(
		&f.ID, &f.TenantID, &f.FindingKey, &f.DedupScope, &f.AssetID, &f.ApplicationID, &f.Track,
		&category, &f.RuleScannerFamily, &f.RuleID, &f.Title, &f.Description,
		&f.CWEs, &f.VulnerabilityID, &locationJSON, &severity, &f.ToolSeverity,
		&overr, &f.CVSSVector, &f.RiskScore, &state, &prevState, &f.StateReason,
		&detection, &f.ContentHash, &f.WeakFingerprint, &f.FirstSeen, &f.LastSeen,
		&f.ResolvedAt, &resolution, &f.ReopenedCount, &f.OccurrenceCount, &f.Version, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	f.Category = domain.FindingCategory(category)
	f.Severity = domain.Severity(severity)
	f.State = domain.FindingState(state)
	f.PreviousState = domain.FindingState(prevState)
	f.Detection = domain.DetectionStatus(detection)
	if overr != "" {
		f.SeverityOverrideReason = &overr
	}
	if resolution != "" {
		r := domain.Resolution(resolution)
		f.Resolution = &r
	}
	if len(locationJSON) > 0 {
		_ = json.Unmarshal(locationJSON, &f.Location)
	}
	return &f, nil
}

// InTenantTx runs fn in one transaction with app.tenant_id set. Every call on the
// store passed to fn joins that transaction, so a merge batch commits or rolls back
// as a unit (D13: "per batch, one transaction").
func (s *PostgresStore) InTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(Store) error) error {
	if s.tx != nil {
		if tenantID != s.txTenant {
			return ErrCrossTenantTx
		}
		return fn(s)
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return fn(&PostgresStore{pool: s.pool, tx: tx, txTenant: tenantID})
	})
}

// LockScope takes the transaction-scoped advisory lock of a close scope so two runs
// on the same scope are serialised while other scopes proceed in parallel (D13).
func (s *PostgresStore) LockScope(ctx context.Context, scope CloseScope) error {
	if s.tx == nil {
		return errors.New("store: LockScope requires InTenantTx")
	}
	_, err := s.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, scope.Key())
	return err
}

// RecomputeOccurrenceCounts sets finding.occurrence_count from the rows, never by
// incrementing, so a retried batch cannot double count (D12).
func (s *PostgresStore) RecomputeOccurrenceCounts(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) error {
	if len(findingIDs) == 0 {
		return nil
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE finding f SET occurrence_count = (
				SELECT count(*) FROM occurrence o
				WHERE o.tenant_id = f.tenant_id AND o.finding_id = f.id AND o.present)
			WHERE f.tenant_id = $1 AND f.id = ANY($2)`, tenantID, findingIDs)
		return err
	})
}

// EnsureScanSource resolves the source an upload belongs to (D10, D3). ref is a source
// id or name; empty means the tenant's built-in "default" source, which is created on
// first use. Any other unknown source is ErrNotFound: sources are configuration.
func (s *PostgresStore) EnsureScanSource(ctx context.Context, tenantID uuid.UUID, ref string) (uuid.UUID, error) {
	if ref == "" {
		ref = "default"
	}
	var id uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var q string
		var arg any = ref
		if parsed, perr := uuid.Parse(ref); perr == nil {
			q, arg = `SELECT id FROM scan_source WHERE tenant_id = $1 AND id = $2`, parsed
		} else {
			q = `SELECT id FROM scan_source WHERE tenant_id = $1 AND name = $2`
		}
		err := tx.QueryRow(ctx, q, tenantID, arg).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			if ref != "default" {
				return ErrNotFound
			}
			return tx.QueryRow(ctx, `
				INSERT INTO scan_source (id, tenant_id, name, type, scanner_family)
				VALUES ($1, $2, 'default', 'upload', 'generic')
				ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name
				RETURNING id`, domain.NewID(), tenantID).Scan(&id)
		}
		return err
	})
	return id, err
}

// GetFindingsByKeys retrieves existing findings within the tenant scope matching keys (D13).
func (s *PostgresStore) GetFindingsByKeys(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]*domain.Finding, error) {
	results := make(map[string]*domain.Finding)
	if len(keys) == 0 {
		return results, nil
	}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM finding WHERE tenant_id = $1 AND finding_key = ANY($2)`, tenantID, keys)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			results[f.FindingKey] = f
		}
		return rows.Err()
	})
	return results, err
}

// UpsertFindings batches findings into the finding table using ON CONFLICT (D13).
func (s *PostgresStore) UpsertFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO finding (
				id, tenant_id, finding_key, dedup_scope, asset_id, application_id, track,
				category, rule_scanner_family, rule_id, title, description, cwes,
				vulnerability_id, location, severity, tool_severity, severity_override_reason,
				cvss_vector, risk_score, state, previous_state, state_reason, detection,
				content_hash, weak_fingerprint, first_seen, last_seen, reopened_count,
				occurrence_count, version, created_at, updated_at, resolved_at, resolution
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
				$14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
				$25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35
			)
			ON CONFLICT (tenant_id, finding_key) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				location = EXCLUDED.location,
				tool_severity = EXCLUDED.tool_severity,
				title = EXCLUDED.title,
				description = EXCLUDED.description,
				severity = CASE
					WHEN finding.severity_override_reason IS NOT NULL THEN finding.severity
					ELSE EXCLUDED.severity
				END,
				cvss_vector = COALESCE(EXCLUDED.cvss_vector, finding.cvss_vector),
				risk_score = EXCLUDED.risk_score,
				state = EXCLUDED.state,
				previous_state = EXCLUDED.previous_state,
				state_reason = EXCLUDED.state_reason,
				resolved_at = EXCLUDED.resolved_at,
				resolution = EXCLUDED.resolution,
				detection = EXCLUDED.detection,
				content_hash = EXCLUDED.content_hash,
				reopened_count = EXCLUDED.reopened_count,
				occurrence_count = EXCLUDED.occurrence_count,
				version = finding.version + 1,
				updated_at = NOW()`

		for _, f := range findings {
			locJSON, _ := json.Marshal(f.Location)
			if len(locJSON) == 0 || string(locJSON) == "null" {
				locJSON = []byte("{}")
			}
			now := time.Now().UTC()
			createdAt := f.CreatedAt
			if createdAt.IsZero() {
				createdAt = now
			}
			updatedAt := f.UpdatedAt
			if updatedAt.IsZero() {
				updatedAt = now
			}

			cwes := f.CWEs
			if cwes == nil {
				cwes = []int{}
			}
			var prevState *string
			if f.PreviousState != "" {
				s := string(f.PreviousState)
				prevState = &s
			}
			var cvssVec *string
			if f.CVSSVector != "" {
				s := f.CVSSVector
				cvssVec = &s
			}
			var stateReason *string
			if f.StateReason != "" {
				s := f.StateReason
				stateReason = &s
			}
			detection := string(f.Detection)
			if detection == "" {
				detection = "present"
			}
			track := f.Track
			if track == "" {
				track = "default"
			}

			var resolution *string
			if f.Resolution != nil {
				r := string(*f.Resolution)
				resolution = &r
			}
			_, err := tx.Exec(ctx, query,
				f.ID, f.TenantID, f.FindingKey, f.DedupScope, f.AssetID, f.ApplicationID, track,
				string(f.Category), f.RuleScannerFamily, f.RuleID, f.Title, f.Description, cwes,
				f.VulnerabilityID, locJSON, string(f.Severity), f.ToolSeverity, f.SeverityOverrideReason,
				cvssVec, f.RiskScore, string(f.State), prevState, stateReason, detection,
				f.ContentHash, f.WeakFingerprint, f.FirstSeen, f.LastSeen, f.ReopenedCount,
				f.OccurrenceCount, f.Version, createdAt, updatedAt, f.ResolvedAt, resolution,
			)
			if err != nil {
				return fmt.Errorf("store: failed to upsert finding %s: %w", f.FindingKey, err)
			}
		}
		return nil
	})
}

// UpsertOccurrences persists occurrences keyed by (tenant_id, finding_id, scan_source_id, occurrence_key) (D12).
func (s *PostgresStore) UpsertOccurrences(ctx context.Context, occurrences []*domain.Occurrence) error {
	if len(occurrences) == 0 {
		return nil
	}
	tenantID := occurrences[0].TenantID

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO occurrence (
				id, tenant_id, finding_id, ingest_run_id, scan_source_id, asset_id, track,
				occurrence_key, scanner_family, scanner_name, scanner_version, tool_record_id,
				location, tool_severity, normalized, raw, present, seen_count, first_seen, last_seen
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
			)
			ON CONFLICT (tenant_id, finding_id, scan_source_id, occurrence_key) DO UPDATE SET
				ingest_run_id = EXCLUDED.ingest_run_id,
				present = EXCLUDED.present,
				seen_count = occurrence.seen_count + 1,
				last_seen = EXCLUDED.last_seen,
				raw = COALESCE(EXCLUDED.raw, occurrence.raw),
				normalized = COALESCE(EXCLUDED.normalized, occurrence.normalized),
				tool_severity = EXCLUDED.tool_severity,
				location = EXCLUDED.location`

		for _, occ := range occurrences {
			locJSON, _ := json.Marshal(occ.Location)
			if len(locJSON) == 0 || string(locJSON) == "null" {
				locJSON = []byte("{}")
			}
			seenCount := occ.SeenCount
			if seenCount <= 0 {
				seenCount = 1
			}
			var scanSourceID *uuid.UUID
			if occ.ScanSourceID != uuid.Nil {
				scanSourceID = &occ.ScanSourceID
			}
			track := occ.Track
			if track == "" {
				track = "default"
			}
			firstSeen := occ.FirstSeen
			if firstSeen.IsZero() {
				firstSeen = time.Now().UTC()
			}
			lastSeen := occ.LastSeen
			if lastSeen.IsZero() {
				lastSeen = time.Now().UTC()
			}

			_, err := tx.Exec(ctx, query,
				occ.ID, occ.TenantID, occ.FindingID, occ.IngestRunID, scanSourceID, occ.AssetID, track,
				occ.OccurrenceKey, occ.ScannerFamily, occ.ScannerName, occ.ScannerVersion, occ.ToolRecordID,
				locJSON, occ.ToolSeverity, occ.Normalized, occ.Raw, occ.Present, seenCount, firstSeen, lastSeen,
			)
			if err != nil {
				return fmt.Errorf("store: failed to upsert occurrence: %w", err)
			}
		}
		return nil
	})
}

// GetActiveScopeOccurrences retrieves present occurrences belonging to the close scope (D13).
func (s *PostgresStore) GetActiveScopeOccurrences(ctx context.Context, scope CloseScope) ([]*domain.Occurrence, error) {
	var occurrences []*domain.Occurrence

	err := s.withTenantTx(ctx, scope.TenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, finding_id, ingest_run_id, scan_source_id, asset_id, track,
			       occurrence_key, scanner_family, scanner_name, coalesce(scanner_version, ''),
			       coalesce(tool_record_id, ''), location, tool_severity, normalized, raw,
			       present, seen_count, first_seen, last_seen
			FROM occurrence
			WHERE tenant_id = $1 AND scan_source_id = $2 AND scanner_family = $3
			  AND asset_id = $4 AND track = $5 AND present = true`

		rows, err := tx.Query(ctx, query, scope.TenantID, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				occ          domain.Occurrence
				locationJSON []byte
			)
			err := rows.Scan(
				&occ.ID, &occ.TenantID, &occ.FindingID, &occ.IngestRunID, &occ.ScanSourceID, &occ.AssetID, &occ.Track,
				&occ.OccurrenceKey, &occ.ScannerFamily, &occ.ScannerName, &occ.ScannerVersion,
				&occ.ToolRecordID, &locationJSON, &occ.ToolSeverity, &occ.Normalized, &occ.Raw,
				&occ.Present, &occ.SeenCount, &occ.FirstSeen, &occ.LastSeen,
			)
			if err != nil {
				return err
			}
			if len(locationJSON) > 0 {
				_ = json.Unmarshal(locationJSON, &occ.Location)
			}
			occurrences = append(occurrences, &occ)
		}
		return rows.Err()
	})

	return occurrences, err
}

// UpdateOccurrencesPresence toggles the present boolean on specified occurrences (D13).
func (s *PostgresStore) UpdateOccurrencesPresence(ctx context.Context, tenantID uuid.UUID, occurrenceIDs []uuid.UUID, present bool) error {
	if len(occurrenceIDs) == 0 {
		return nil
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `UPDATE occurrence SET present = $1 WHERE tenant_id = $2 AND id = ANY($3)`
		_, err := tx.Exec(ctx, query, present, tenantID, occurrenceIDs)
		return err
	})
}

// GetActiveScopeFindings retrieves findings in active states for an asset and track (D13).
func (s *PostgresStore) GetActiveScopeFindings(ctx context.Context, tenantID, assetID uuid.UUID, track string) ([]*domain.Finding, error) {
	var findings []*domain.Finding
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM finding
			WHERE tenant_id = $1 AND asset_id = $2 AND track = $3
			  AND state IN ('open', 'under_investigation', 'affected')`, tenantID, assetID, track)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			findings = append(findings, f)
		}
		return rows.Err()
	})
	return findings, err
}

// CountPresentOccurrences counts the number of present occurrences for a finding (D12).
func (s *PostgresStore) CountPresentOccurrences(ctx context.Context, tenantID, findingID uuid.UUID) (int, error) {
	var count int
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT COUNT(*) FROM occurrence WHERE tenant_id = $1 AND finding_id = $2 AND present = true`
		return tx.QueryRow(ctx, query, tenantID, findingID).Scan(&count)
	})
	return count, err
}

// CountPresentOccurrencesBatch counts present occurrences for many findings in one query.
// Findings with none are absent from the map (count 0).
func (s *PostgresStore) CountPresentOccurrencesBatch(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	out := make(map[uuid.UUID]int, len(findingIDs))
	if len(findingIDs) == 0 {
		return out, nil
	}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT finding_id, count(*) FROM occurrence
			WHERE tenant_id = $1 AND finding_id = ANY($2) AND present GROUP BY finding_id`, tenantID, findingIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				return err
			}
			out[id] = n
		}
		return rows.Err()
	})
	return out, err
}

// CheckScopeOrdering checks whether the incoming scanFinished timestamp is older than the last applied scan (D13 line 204).
func (s *PostgresStore) CheckScopeOrdering(scope CloseScope, scanFinished time.Time) (bool, error) {
	if scanFinished.IsZero() {
		return false, nil
	}

	query := `
		SELECT MAX(r.scan_finished)
		FROM ingest_run r
		JOIN ingest_run_scope s ON s.ingest_run_id = r.id AND s.tenant_id = r.tenant_id
		WHERE s.tenant_id = $1 AND s.scan_source_id = $2 AND s.scanner_family = $3
		  AND s.asset_id = $4 AND s.track = $5 AND r.status = 'completed'`

	// ingest_run and ingest_run_scope are under FORCE RLS: without the tenant
	// context the query silently sees zero rows and no run is ever stale.
	var latest *time.Time
	err := s.withTenantTx(context.Background(), scope.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query,
			scope.TenantID, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track).Scan(&latest)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	if latest != nil && scanFinished.Before(*latest) {
		return true, nil
	}
	return false, nil
}

// RecordFindingEvents persists audit trail events into the partitioned finding_event table (D12, D25).
func (s *PostgresStore) RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error {
	if len(events) == 0 {
		return nil
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO finding_event (id, tenant_id, finding_id, at, actor, type, "from", "to", note)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

		for _, ev := range events {
			id := ev.ID
			if id == domain.NilID {
				id = domain.NewID()
			}
			at := ev.At
			if at.IsZero() {
				at = time.Now().UTC()
			}
			_, err := tx.Exec(ctx, query, id, tenantID, ev.FindingID, at, ev.Actor, ev.Type, ev.From, ev.To, ev.Note)
			if err != nil {
				return fmt.Errorf("store: failed to record finding event: %w", err)
			}
		}
		return nil
	})
}

// GetFindingEvents retrieves the chronological event timeline for a finding (D12, D18).
func (s *PostgresStore) GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error) {
	var events []*domain.FindingEvent

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, finding_id, at, actor, type, "from", "to", coalesce(note, '')
			FROM finding_event
			WHERE tenant_id = $1 AND finding_id = $2
			ORDER BY at ASC`

		rows, err := tx.Query(ctx, query, tenantID, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var ev domain.FindingEvent
			if err := rows.Scan(&ev.ID, &ev.FindingID, &ev.At, &ev.Actor, &ev.Type, &ev.From, &ev.To, &ev.Note); err != nil {
				return err
			}
			events = append(events, &ev)
		}
		return rows.Err()
	})

	return events, err
}

// ListFindings retrieves all findings for a tenant (used by Query API D14).
func (s *PostgresStore) ListFindings(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error) {
	var findings []*domain.Finding
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM finding WHERE tenant_id = $1
			ORDER BY risk_score DESC, last_seen DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			findings = append(findings, f)
		}
		return rows.Err()
	})
	return findings, err
}

// GetFinding retrieves a finding and its active occurrences (D14).
func (s *PostgresStore) GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*domain.Finding, []*domain.Occurrence, error) {
	var (
		f           *domain.Finding
		occurrences []*domain.Occurrence
	)

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		f, err = scanFinding(tx.QueryRow(ctx, `SELECT `+findingCols+` FROM finding WHERE tenant_id = $1 AND id = $2`, tenantID, findingID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		// Fetch occurrences
		occQuery := `
			SELECT id, tenant_id, finding_id, ingest_run_id, scan_source_id, asset_id, track,
			       occurrence_key, scanner_family, scanner_name, coalesce(scanner_version, ''),
			       coalesce(tool_record_id, ''), location, tool_severity, normalized, raw,
			       present, seen_count, first_seen, last_seen
			FROM occurrence
			WHERE tenant_id = $1 AND finding_id = $2
			ORDER BY present DESC, last_seen DESC`

		rows, err := tx.Query(ctx, occQuery, tenantID, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				occ        domain.Occurrence
				occLocJSON []byte
			)
			if err := rows.Scan(
				&occ.ID, &occ.TenantID, &occ.FindingID, &occ.IngestRunID, &occ.ScanSourceID, &occ.AssetID, &occ.Track,
				&occ.OccurrenceKey, &occ.ScannerFamily, &occ.ScannerName, &occ.ScannerVersion,
				&occ.ToolRecordID, &occLocJSON, &occ.ToolSeverity, &occ.Normalized, &occ.Raw,
				&occ.Present, &occ.SeenCount, &occ.FirstSeen, &occ.LastSeen,
			); err != nil {
				return err
			}
			if len(occLocJSON) > 0 {
				_ = json.Unmarshal(occLocJSON, &occ.Location)
			}
			occurrences = append(occurrences, &occ)
		}
		return rows.Err()
	})

	if err != nil {
		return nil, nil, err
	}
	return f, occurrences, nil
}

// LookupAsset queries an asset by natural key (tenant_id, type, key) (D10).
func (s *PostgresStore) LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error) {
	var a domain.Asset
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, application_id, service_id, environment_id, type, key, display_name, active, first_seen, last_seen
			FROM asset
			WHERE tenant_id = $1 AND type = $2 AND key = $3`

		var typeStr string
		err := tx.QueryRow(ctx, query, tenantID, string(assetType), key).Scan(
			&a.ID, &a.TenantID, &a.ApplicationID, &a.ServiceID, &a.EnvironmentID,
			&typeStr, &a.Key, &a.DisplayName, &a.Active, &a.FirstSeen, &a.LastSeen,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		a.Type = domain.AssetType(typeStr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateAsset persists a new asset record (D10).
func (s *PostgresStore) CreateAsset(ctx context.Context, asset *domain.Asset) error {
	return s.withTenantTx(ctx, asset.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO asset (id, tenant_id, application_id, service_id, environment_id, type, key, display_name, active, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, type, key) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), asset.display_name)`

		now := time.Now().UTC()
		firstSeen := asset.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = now
		}
		lastSeen := asset.LastSeen
		if lastSeen.IsZero() {
			lastSeen = now
		}

		_, err := tx.Exec(ctx, query,
			asset.ID, asset.TenantID, asset.ApplicationID, asset.ServiceID, asset.EnvironmentID,
			string(asset.Type), asset.Key, asset.DisplayName, asset.Active, firstSeen, lastSeen,
		)
		return err
	})
}

// LookupApplication queries an application by slug within a tenant (D10).
func (s *PostgresStore) LookupApplication(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error) {
	var app domain.Application
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, slug, name, coalesce(description, ''), business_criticality, internet_facing, lifecycle, version, created_at
			FROM application
			WHERE tenant_id = $1 AND slug = $2`

		err := tx.QueryRow(ctx, query, tenantID, slug).Scan(
			&app.ID, &app.TenantID, &app.Slug, &app.Name, &app.Description,
			&app.BusinessCriticality, &app.InternetFacing, &app.Lifecycle, &app.Version, &app.CreatedAt,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &app, nil
}

// CreateApplication inserts or updates an application (D10).
func (s *PostgresStore) CreateApplication(ctx context.Context, app *domain.Application) error {
	return s.withTenantTx(ctx, app.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO application (id, tenant_id, slug, name, description, business_criticality, internet_facing, lifecycle, version, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant_id, slug) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				version = application.version + 1`

		createdAt := app.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		version := app.Version
		if version <= 0 {
			version = 1
		}

		_, err := tx.Exec(ctx, query,
			app.ID, app.TenantID, app.Slug, app.Name, app.Description,
			app.BusinessCriticality, app.InternetFacing, app.Lifecycle, version, createdAt,
		)
		return err
	})
}

// CreateIngestRun records an ingestion run (D2).
func (s *PostgresStore) CreateIngestRun(ctx context.Context, run *domain.IngestRun) error {
	return s.withTenantTx(ctx, run.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO ingest_run (
				id, tenant_id, upload_id, scan_source_id, application_id, asset_id, track,
				scanner_family, scanner_version, format, status, scan_started, scan_finished, stats, created_at, context
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

		statsJSON, _ := json.Marshal(run.Stats)
		ctxJSON, _ := json.Marshal(run.Context)
		createdAt := run.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		var scanSourceID *uuid.UUID
		if run.ScanSourceID != uuid.Nil {
			scanSourceID = &run.ScanSourceID
		}
		var scanStarted *time.Time
		if !run.ScanStarted.IsZero() {
			scanStarted = &run.ScanStarted
		}
		var scanFinished *time.Time
		if !run.ScanFinished.IsZero() {
			scanFinished = &run.ScanFinished
		}

		_, err := tx.Exec(ctx, query,
			run.ID, run.TenantID, run.UploadID, scanSourceID, run.ApplicationID, run.AssetID, run.Track,
			run.ScannerFamily, run.ScannerVersion, run.Format, string(run.Status),
			scanStarted, scanFinished, statsJSON, createdAt, ctxJSON,
		)
		return err
	})
}

// GetIngestRun fetches an ingest run by id (D2).
func (s *PostgresStore) GetIngestRun(ctx context.Context, tenantID, runID uuid.UUID) (*domain.IngestRun, error) {
	var run domain.IngestRun
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, upload_id, scan_source_id, application_id, asset_id, track,
			       scanner_family, coalesce(scanner_version, ''), format, status,
			       scan_started, scan_finished, stats, coalesce(error, ''), created_at, finished_at
			FROM ingest_run
			WHERE tenant_id = $1 AND id = $2`

		var (
			statsJSON    []byte
			statusStr    string
			scanSourceID *uuid.UUID
			scanStarted  *time.Time
			scanFinished *time.Time
			finishedAt   *time.Time
		)
		err := tx.QueryRow(ctx, query, tenantID, runID).Scan(
			&run.ID, &run.TenantID, &run.UploadID, &scanSourceID, &run.ApplicationID, &run.AssetID, &run.Track,
			&run.ScannerFamily, &run.ScannerVersion, &run.Format, &statusStr,
			&scanStarted, &scanFinished, &statsJSON, &run.Error, &run.CreatedAt, &finishedAt,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if scanSourceID != nil {
			run.ScanSourceID = *scanSourceID
		}
		if scanStarted != nil {
			run.ScanStarted = *scanStarted
		}
		if scanFinished != nil {
			run.ScanFinished = *scanFinished
		}
		run.FinishedAt = finishedAt
		run.Status = domain.IngestRunStatus(statusStr)
		if len(statsJSON) > 0 {
			_ = json.Unmarshal(statsJSON, &run.Stats)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// UpdateIngestRun updates an ingest run status and statistics (D2).
func (s *PostgresStore) UpdateIngestRun(ctx context.Context, run *domain.IngestRun) error {
	return s.withTenantTx(ctx, run.TenantID, func(tx pgx.Tx) error {
		query := `
			UPDATE ingest_run
			SET status = $1, stats = $2, finished_at = $3, error = $4
			WHERE tenant_id = $5 AND id = $6`

		statsJSON, _ := json.Marshal(run.Stats)
		_, err := tx.Exec(ctx, query, string(run.Status), statsJSON, run.FinishedAt, run.Error, run.TenantID, run.ID)
		return err
	})
}

// RecordRunScope links an asset/track scope to an ingest run (D10, D13).
func (s *PostgresStore) RecordRunScope(ctx context.Context, scope *domain.IngestRunScope) error {
	return s.withTenantTx(ctx, scope.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO ingest_run_scope (ingest_run_id, tenant_id, scan_source_id, scanner_family, asset_id, track)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (ingest_run_id, asset_id, track, scanner_family) DO NOTHING`

		_, err := tx.Exec(ctx, query, scope.IngestRunID, scope.TenantID, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track)
		return err
	})
}

// RecordRunResult records ephemeral scan run findings without polluting main inventory (D10).
func (s *PostgresStore) RecordRunResult(ctx context.Context, result *domain.IngestRunResult) error {
	return s.withTenantTx(ctx, result.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO ingest_run_result (id, tenant_id, ingest_run_id, finding_key, is_new, is_fixed, severity, category, location, raw_payload, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

		locJSON, _ := json.Marshal(result.Location)
		createdAt := result.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		_, err := tx.Exec(ctx, query,
			domain.NewID(), result.TenantID, result.IngestRunID, result.FindingKey, result.IsNew, result.IsFixed,
			string(result.Severity), string(result.Category), locJSON, result.RawPayload, createdAt,
		)
		return err
	})
}

// SaveSBOM saves an SBOM and its components (docs/12).
func (s *PostgresStore) SaveSBOM(ctx context.Context, sbom *domain.SBOM, components []domain.SBOMComponent) error {
	return s.withTenantTx(ctx, sbom.TenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO sbom (id, tenant_id, asset_id, ingest_run_id, format, spec_version, serial, object_ref, root_component, component_count, dependencies, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

		depsJSON, _ := json.Marshal(sbom.Dependencies)
		createdAt := sbom.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		_, err := tx.Exec(ctx, query,
			sbom.ID, sbom.TenantID, sbom.AssetID, sbom.IngestRunID, sbom.Format, sbom.SpecVersion,
			sbom.Serial, sbom.ObjectRef, sbom.RootComponent, sbom.ComponentCount, depsJSON, createdAt,
		)
		if err != nil {
			return err
		}

		compQuery := `
			INSERT INTO sbom_component (tenant_id, sbom_id, ref, purl, purl_base, name, version, licenses, scope, direct, hashes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, sbom_id, ref) DO UPDATE SET
				purl = EXCLUDED.purl,
				version = EXCLUDED.version`

		for _, c := range components {
			hashesJSON, _ := json.Marshal(c.Hashes)
			if len(hashesJSON) == 0 || string(hashesJSON) == "null" {
				hashesJSON = []byte("{}")
			}
			licenses := c.Licenses
			if licenses == nil {
				licenses = []string{}
			}
			_, err := tx.Exec(ctx, compQuery,
				c.TenantID, sbom.ID, c.Ref, c.Purl, c.PurlBase, c.Name, c.Version, licenses, c.Scope, c.Direct, hashesJSON,
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetSBOM retrieves the latest SBOM and its components for an asset (docs/12).
func (s *PostgresStore) GetSBOM(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error) {
	var (
		sbom       domain.SBOM
		components []domain.SBOMComponent
	)

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, asset_id, ingest_run_id, format, spec_version, serial, coalesce(object_ref, ''),
			       coalesce(root_component, ''), component_count, dependencies, created_at
			FROM sbom
			WHERE tenant_id = $1 AND asset_id = $2
			ORDER BY created_at DESC
			LIMIT 1`

		var depsJSON []byte
		err := tx.QueryRow(ctx, query, tenantID, assetID).Scan(
			&sbom.ID, &sbom.TenantID, &sbom.AssetID, &sbom.IngestRunID, &sbom.Format, &sbom.SpecVersion,
			&sbom.Serial, &sbom.ObjectRef, &sbom.RootComponent, &sbom.ComponentCount, &depsJSON, &sbom.CreatedAt,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if len(depsJSON) > 0 {
			_ = json.Unmarshal(depsJSON, &sbom.Dependencies)
		}

		compQuery := `
			SELECT ref, purl, purl_base, name, version, licenses, coalesce(scope, ''), direct, hashes
			FROM sbom_component
			WHERE tenant_id = $1 AND sbom_id = $2`

		rows, err := tx.Query(ctx, compQuery, tenantID, sbom.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				c          domain.SBOMComponent
				hashesJSON []byte
			)
			c.TenantID = tenantID
			c.SBOMID = sbom.ID
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

// LookupTokenByHash retrieves an API token record by its SHA-256 hash (D8).
// It runs under the tenant's RLS context, so a token of another tenant is invisible.
func (s *PostgresStore) LookupTokenByHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*auth.TokenRecord, error) {
	var rec auth.TokenRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var (
			name, roleStr string
			expiresAt     *time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, encode(hash, 'hex'), role, scopes, expires_at, created_at
			FROM api_token
			WHERE tenant_id = $1 AND hash = decode($2, 'hex') AND revoked_at IS NULL`, tenantID, tokenHash).Scan(
			&rec.ID, &rec.TenantID, &name, &rec.TokenHash, &roleStr, &rec.Scopes, &expiresAt, &rec.CreatedAt)
		if err != nil {
			return err
		}
		rec.Subject = name
		rec.Role = auth.Role(roleStr)
		if expiresAt != nil {
			rec.ExpiresAt = *expiresAt
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// SaveToken persists or updates an API token record (D8).
func (s *PostgresStore) SaveToken(ctx context.Context, record *auth.TokenRecord) error {
	query := `
		INSERT INTO api_token (id, tenant_id, name, prefix, hash, role, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, decode($5, 'hex'), $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			role = EXCLUDED.role,
			scopes = EXCLUDED.scopes,
			expires_at = EXCLUDED.expires_at`

	var expiresAt *time.Time
	if !record.ExpiresAt.IsZero() {
		expiresAt = &record.ExpiresAt
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	prefix := "rpt_"
	if len(record.TokenHash) >= 8 {
		prefix = record.TokenHash[:8]
	}

	return s.withTenantTx(ctx, record.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query,
			record.ID, record.TenantID, record.Subject, prefix, record.TokenHash, string(record.Role),
			record.Scopes, expiresAt, createdAt,
		)
		return err
	})
}

// CreateTenant inserts a new tenant into the global tenant table (D4, D8).
func (s *PostgresStore) CreateTenant(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		INSERT INTO tenant (id, slug, display_name, k8s_namespace, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (slug) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			k8s_namespace = EXCLUDED.k8s_namespace`

	createdAt := tenant.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, query, tenant.ID, tenant.Slug, tenant.DisplayName, tenant.K8sNamespace, createdAt)
	return err
}

// GetTenant fetches a tenant by UUID (D4, D8).
func (s *PostgresStore) GetTenant(ctx context.Context, tenantID uuid.UUID) (*domain.Tenant, error) {
	query := `SELECT id, slug, display_name, coalesce(k8s_namespace, ''), created_at FROM tenant WHERE id = $1`
	var t domain.Tenant
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(&t.ID, &t.Slug, &t.DisplayName, &t.K8sNamespace, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// SaveTenant implements apply.ConfigStore.
func (s *PostgresStore) SaveTenant(ctx context.Context, tenant domain.Tenant) error {
	return s.CreateTenant(ctx, &tenant)
}

// GetTenantBySlug implements apply.ConfigStore.
func (s *PostgresStore) GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	query := `SELECT id, slug, display_name, coalesce(k8s_namespace, ''), created_at FROM tenant WHERE slug = $1`
	var t domain.Tenant
	err := s.pool.QueryRow(ctx, query, slug).Scan(&t.ID, &t.Slug, &t.DisplayName, &t.K8sNamespace, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// ClaimNamespace binds a namespace to a tenant (D20). A namespace has one owner.
// Written by rampart_system only (the operator path).
func (s *PostgresStore) ClaimNamespace(ctx context.Context, tenantID uuid.UUID, namespace string) error {
	var owner uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant_namespace (namespace, tenant_id) VALUES ($1, $2)
		ON CONFLICT (namespace) DO UPDATE SET namespace = EXCLUDED.namespace
		RETURNING tenant_id`, namespace, tenantID).Scan(&owner)
	if err != nil {
		return err
	}
	if owner != tenantID {
		return apply.ErrNamespaceOwned
	}
	return nil
}

// GetTenantByNamespace returns the tenant that lists the namespace in spec.namespaces (D20).
func (s *PostgresStore) GetTenantByNamespace(ctx context.Context, namespace string) (*domain.Tenant, error) {
	var t domain.Tenant
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.slug, t.display_name, coalesce(t.k8s_namespace, ''), t.created_at
		FROM tenant_namespace n JOIN tenant t ON t.id = n.tenant_id WHERE n.namespace = $1`, namespace).
		Scan(&t.ID, &t.Slug, &t.DisplayName, &t.K8sNamespace, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SaveApplication implements apply.ConfigStore.
func (s *PostgresStore) SaveApplication(ctx context.Context, app domain.Application) error {
	return s.CreateApplication(ctx, &app)
}

// GetApplicationBySlug implements apply.ConfigStore.
func (s *PostgresStore) GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error) {
	app, err := s.LookupApplication(ctx, tenantID, slug)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return app, nil
}

// SaveScanSource implements apply.ConfigStore.
func (s *PostgresStore) SaveScanSource(ctx context.Context, tenantID uuid.UUID, name string, scannerFamily string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO scan_source (id, tenant_id, name, type, scanner_family, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, name) DO UPDATE SET
				scanner_family = EXCLUDED.scanner_family
			RETURNING id`
		scanType := scannerFamily
		if scanType == "" {
			scanType = "generic"
		}
		newID := domain.NewID()
		return tx.QueryRow(ctx, query, newID, tenantID, name, scanType, scannerFamily, time.Now().UTC()).Scan(&id)
	})
	return id, err
}

// SaveSecretMaterial stores encrypted credentials into secret_material (D4 line 30).
func (s *PostgresStore) SaveSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string, encryptedValue []byte) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO secret_material (id, tenant_id, key, encrypted_value, version, created_at)
			VALUES ($1, $2, $3, $4, 1, $5)
			ON CONFLICT (tenant_id, key) DO UPDATE SET
				encrypted_value = EXCLUDED.encrypted_value,
				version = secret_material.version + 1`
		_, err := tx.Exec(ctx, query, domain.NewID(), tenantID, key, encryptedValue, time.Now().UTC())
		return err
	})
}

// GetSecretMaterial retrieves encrypted credentials from secret_material (D4 line 30).
func (s *PostgresStore) GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error) {
	var val []byte
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT encrypted_value FROM secret_material WHERE tenant_id = $1 AND key = $2`
		err := tx.QueryRow(ctx, query, tenantID, key).Scan(&val)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		return nil
	})
	return val, err
}
