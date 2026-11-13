package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// DTrackStore defines data access methods for Dependency-Track sync state and portfolio tracking.
type DTrackStore interface {
	EnqueueDTrackSync(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) (shouldStart bool, err error)
	CompleteDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string, syncErr error) (hasTrailing bool, err error)
	GetDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.DTrackSync, error)
	UpsertDTrackProject(ctx context.Context, proj domain.DTrackProjectRecord) error
	ListUnmappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error)
	LookupScanSource(ctx context.Context, sourceID uuid.UUID) (tenantID uuid.UUID, name string, err error)
}

// LookupScanSource finds the tenant and name of a ScanSource by its UUID.
func (s *PostgresStore) LookupScanSource(ctx context.Context, sourceID uuid.UUID) (uuid.UUID, string, error) {
	var tenantID uuid.UUID
	var name string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, name FROM scan_source WHERE id = $1`, sourceID).Scan(&tenantID, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return tenantID, name, nil
}

// EnqueueDTrackSync implements trailing-edge debouncing state transition (docs/21 §4.3).
func (s *PostgresStore) EnqueueDTrackSync(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) (bool, error) {
	var shouldStart bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var state string
		var dirty bool
		query := `SELECT state, dirty FROM dtrack_sync WHERE tenant_id = $1 AND project_uuid = $2 FOR UPDATE`
		err := tx.QueryRow(ctx, query, tenantID, projectUUID).Scan(&state, &dirty)
		if errors.Is(err, pgx.ErrNoRows) {
			// No record: start sync immediately
			ins := `INSERT INTO dtrack_sync (tenant_id, project_uuid, source_id, state, dirty, last_sync_at, created_at, updated_at)
			        VALUES ($1, $2, $3, 'syncing', FALSE, NOW(), NOW(), NOW())`
			_, insErr := tx.Exec(ctx, ins, tenantID, projectUUID, sourceID)
			if insErr != nil {
				return fmt.Errorf("inserting dtrack_sync: %w", insErr)
			}
			shouldStart = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("checking dtrack_sync: %w", err)
		}

		if state == string(domain.DTrackSyncStateSyncing) {
			// Already running: mark dirty so another sync will run after completion
			_, upErr := tx.Exec(ctx, `UPDATE dtrack_sync SET dirty = TRUE, updated_at = NOW() WHERE tenant_id = $1 AND project_uuid = $2`, tenantID, projectUUID)
			if upErr != nil {
				return fmt.Errorf("marking dtrack_sync dirty: %w", upErr)
			}
			shouldStart = false
			return nil
		}

		// Currently idle: start new sync run
		_, upErr := tx.Exec(ctx, `UPDATE dtrack_sync SET state = 'syncing', dirty = FALSE, last_sync_at = NOW(), updated_at = NOW() WHERE tenant_id = $1 AND project_uuid = $2`, tenantID, projectUUID)
		if upErr != nil {
			return fmt.Errorf("updating dtrack_sync to syncing: %w", upErr)
		}
		shouldStart = true
		return nil
	})
	return shouldStart, err
}

// CompleteDTrackSync handles trailing-edge completion: triggers another sync if dirty was set (docs/21 §4.3).
func (s *PostgresStore) CompleteDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string, syncErr error) (bool, error) {
	var hasTrailing bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var dirty bool
		query := `SELECT dirty FROM dtrack_sync WHERE tenant_id = $1 AND project_uuid = $2 FOR UPDATE`
		err := tx.QueryRow(ctx, query, tenantID, projectUUID).Scan(&dirty)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("checking dirty flag on completion: %w", err)
		}

		errMsg := ""
		if syncErr != nil {
			errMsg = syncErr.Error()
		}

		if dirty {
			// Reset dirty, remain in syncing state to execute trailing sync pass
			_, upErr := tx.Exec(ctx, `UPDATE dtrack_sync SET dirty = FALSE, state = 'syncing', last_sync_at = NOW(), last_error = $3, updated_at = NOW() WHERE tenant_id = $1 AND project_uuid = $2`, tenantID, projectUUID, errMsg)
			if upErr != nil {
				return fmt.Errorf("resetting dirty for trailing sync: %w", upErr)
			}
			hasTrailing = true
			return nil
		}

		// No dirty events accumulated: transition back to idle
		_, upErr := tx.Exec(ctx, `UPDATE dtrack_sync SET state = 'idle', last_error = $3, updated_at = NOW() WHERE tenant_id = $1 AND project_uuid = $2`, tenantID, projectUUID, errMsg)
		if upErr != nil {
			return fmt.Errorf("updating dtrack_sync to idle: %w", upErr)
		}
		hasTrailing = false
		return nil
	})
	return hasTrailing, err
}

// GetDTrackSync retrieves the sync record for a project.
func (s *PostgresStore) GetDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.DTrackSync, error) {
	var rec domain.DTrackSync
	var lastSyncAt, nextAt sql.NullTime
	var lastError sql.NullString

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT tenant_id, project_uuid, source_id, state, dirty, last_sync_at, next_at, last_error, created_at, updated_at
		          FROM dtrack_sync WHERE tenant_id = $1 AND project_uuid = $2`
		return tx.QueryRow(ctx, query, tenantID, projectUUID).Scan(
			&rec.TenantID, &rec.ProjectUUID, &rec.SourceID, &rec.State, &rec.Dirty,
			&lastSyncAt, &nextAt, &lastError, &rec.CreatedAt, &rec.UpdatedAt,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastSyncAt.Valid {
		rec.LastSyncAt = &lastSyncAt.Time
	}
	if nextAt.Valid {
		rec.NextAt = &nextAt.Time
	}
	if lastError.Valid {
		rec.LastError = lastError.String
	}
	return &rec, nil
}

// UpsertDTrackProject records or updates portfolio project discovery and mapping.
func (s *PostgresStore) UpsertDTrackProject(ctx context.Context, proj domain.DTrackProjectRecord) error {
	return s.withTenantTx(ctx, proj.TenantID, func(tx pgx.Tx) error {
		query := `INSERT INTO dtrack_project (
			tenant_id, source_id, project_uuid, name, version, purl, active,
			last_bom_import, application_id, mapping_rule, unmapped_reason, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()
		) ON CONFLICT (tenant_id, project_uuid) DO UPDATE SET
			name = EXCLUDED.name,
			version = EXCLUDED.version,
			purl = EXCLUDED.purl,
			active = EXCLUDED.active,
			last_bom_import = EXCLUDED.last_bom_import,
			application_id = EXCLUDED.application_id,
			mapping_rule = EXCLUDED.mapping_rule,
			unmapped_reason = EXCLUDED.unmapped_reason,
			updated_at = NOW()`

		var lastBom *time.Time
		if proj.LastBomImport != nil {
			lastBom = proj.LastBomImport
		}

		_, err := tx.Exec(ctx, query,
			proj.TenantID, proj.SourceID, proj.ProjectUUID, proj.Name, proj.Version, proj.Purl, proj.Active,
			lastBom, proj.ApplicationID, proj.MappingRule, proj.UnmappedReason,
		)
		return err
	})
}

// ListUnmappedDTrackProjects lists portfolio projects that did not match any mapping rule.
func (s *PostgresStore) ListUnmappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error) {
	var results []domain.DTrackProjectRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `SELECT tenant_id, source_id, project_uuid, name, version, purl, active,
		                 last_bom_import, application_id, mapping_rule, unmapped_reason, created_at, updated_at
		          FROM dtrack_project
		          WHERE tenant_id = $1 AND source_id = $2 AND application_id IS NULL
		          ORDER BY name ASC`
		rows, err := tx.Query(ctx, query, tenantID, sourceID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var r domain.DTrackProjectRecord
			var lastBom sql.NullTime
			var appID *uuid.UUID
			var rule, reason sql.NullString
			if err := rows.Scan(
				&r.TenantID, &r.SourceID, &r.ProjectUUID, &r.Name, &r.Version, &r.Purl, &r.Active,
				&lastBom, &appID, &rule, &reason, &r.CreatedAt, &r.UpdatedAt,
			); err != nil {
				return err
			}
			if lastBom.Valid {
				r.LastBomImport = &lastBom.Time
			}
			r.ApplicationID = appID
			if rule.Valid {
				r.MappingRule = rule.String
			}
			if reason.Valid {
				r.UnmappedReason = reason.String
			}
			results = append(results, r)
		}
		return rows.Err()
	})
	return results, err
}
