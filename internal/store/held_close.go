package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// HeldCloses manages held close records and their resolution (D22, Section 3.2).
type HeldCloses interface {
	CreateHeldClose(ctx context.Context, tenantID uuid.UUID, hc *domain.HeldClose) error
	GetHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.HeldClose, error)
	ListHeldCloses(ctx context.Context, tenantID uuid.UUID, decision string) ([]domain.HeldClose, error)
	DecideHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decision string, decidedBy string) error
	ApplyHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decidedBy string) (int, error)
	SupersedeHeldCloses(ctx context.Context, tenantID uuid.UUID, scope domain.CloseScope, byRunID uuid.UUID) (int, error)
}

// ErrHeldCloseSuperseded is returned by ApplyHeldClose when a newer run of the same scope has completed: the hold
// is marked superseded and nothing is closed (D83).
var ErrHeldCloseSuperseded = errors.New("held close superseded by a newer run of the same scope; nothing was closed")

// SupersedeHeldCloses marks every pending hold of a scope, other than one made by byRunID, as superseded. It is
// called when a run of that scope completes its close step, held or not: a newer run describes the scope, so an
// older hold is no longer a decision anyone should take, and the "held close pending" alert stops (D83).
func (s *PostgresStore) SupersedeHeldCloses(ctx context.Context, tenantID uuid.UUID, scope domain.CloseScope, byRunID uuid.UUID) (int, error) {
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		res, err := tx.Exec(ctx, `
			UPDATE held_close SET decision = $4, decided_by = $5, decided_at = now()
			WHERE tenant_id = $1 AND scope = $2::jsonb AND ingest_run_id <> $3 AND (decision IS NULL OR decision = '')`,
			tenantID, scopeJSON, byRunID, domain.HeldCloseDecisionSuperseded, "system:run:"+byRunID.String())
		if err == nil {
			n = int(res.RowsAffected())
		}
		return err
	})
	return n, err
}

func (s *PostgresStore) CreateHeldClose(ctx context.Context, tenantID uuid.UUID, hc *domain.HeldClose) error {
	if hc.ID == uuid.Nil {
		hc.ID = domain.NewID()
	}
	if hc.CreatedAt.IsZero() {
		hc.CreatedAt = time.Now().UTC()
	}
	scopeJSON, err := json.Marshal(hc.Scope)
	if err != nil {
		return fmt.Errorf("store: failed to marshal scope: %w", err)
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO held_close (id, tenant_id, ingest_run_id, scope, finding_ids, created_at, decided_by, decision, decided_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
		var decidedBy, decision *string
		if hc.DecidedBy != "" {
			decidedBy = &hc.DecidedBy
		}
		if hc.Decision != "" {
			decision = &hc.Decision
		}
		_, err := tx.Exec(ctx, query, hc.ID, tenantID, hc.IngestRunID, scopeJSON, hc.FindingIDs, hc.CreatedAt, decidedBy, decision, hc.DecidedAt)
		return err
	})
}

func (s *PostgresStore) GetHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.HeldClose, error) {
	var hc domain.HeldClose
	var scopeRaw []byte
	var decidedBy, decision *string
	var decidedAt *time.Time
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, ingest_run_id, scope, finding_ids, created_at, decided_by, decision, decided_at
			FROM held_close WHERE tenant_id = $1 AND id = $2`
		return tx.QueryRow(ctx, query, tenantID, id).Scan(
			&hc.ID, &hc.TenantID, &hc.IngestRunID, &scopeRaw, &hc.FindingIDs, &hc.CreatedAt, &decidedBy, &decision, &decidedAt,
		)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(scopeRaw, &hc.Scope); err != nil {
		return nil, fmt.Errorf("store: failed to unmarshal scope: %w", err)
	}
	if decidedBy != nil {
		hc.DecidedBy = *decidedBy
	}
	if decision != nil {
		hc.Decision = *decision
	}
	hc.DecidedAt = decidedAt
	return &hc, nil
}

func (s *PostgresStore) ListHeldCloses(ctx context.Context, tenantID uuid.UUID, decision string) ([]domain.HeldClose, error) {
	var out []domain.HeldClose
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT id, tenant_id, ingest_run_id, scope, finding_ids, created_at, decided_by, decision, decided_at
			FROM held_close
			WHERE tenant_id = $1 AND ($2 = '' OR coalesce(decision, '') = $2)
			ORDER BY created_at DESC LIMIT 100`
		rows, err := tx.Query(ctx, query, tenantID, decision)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var hc domain.HeldClose
			var scopeRaw []byte
			var decidedBy, dec *string
			var decidedAt *time.Time
			if err := rows.Scan(&hc.ID, &hc.TenantID, &hc.IngestRunID, &scopeRaw, &hc.FindingIDs, &hc.CreatedAt, &decidedBy, &dec, &decidedAt); err != nil {
				return err
			}
			_ = json.Unmarshal(scopeRaw, &hc.Scope)
			if decidedBy != nil {
				hc.DecidedBy = *decidedBy
			}
			if dec != nil {
				hc.Decision = *dec
			}
			hc.DecidedAt = decidedAt
			out = append(out, hc)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) DecideHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decision string, decidedBy string) error {
	now := time.Now().UTC()
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		res, err := tx.Exec(ctx, `
			UPDATE held_close
			SET decision = $3, decided_by = $4, decided_at = $5
			WHERE tenant_id = $1 AND id = $2 AND (decision IS NULL OR decision = '')`,
			tenantID, id, decision, decidedBy, now)
		if err != nil {
			return err
		}
		if res.RowsAffected() == 0 {
			return errors.New("held close not found or already decided")
		}
		return nil
	})
}

func (s *PostgresStore) ApplyHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decidedBy string) (int, error) {
	now := time.Now().UTC()
	closedCount := 0
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var scopeRaw []byte
		var findingIDs []uuid.UUID
		var existingDecision *string
		var ingestRunID uuid.UUID
		query := `
			SELECT ingest_run_id, scope, finding_ids, decision
			FROM held_close WHERE tenant_id = $1 AND id = $2 FOR UPDATE`
		if err := tx.QueryRow(ctx, query, tenantID, id).Scan(&ingestRunID, &scopeRaw, &findingIDs, &existingDecision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("held close not found")
			}
			return err
		}
		if existingDecision != nil && *existingDecision != "" {
			return errors.New("held close already decided")
		}

		var scope domain.CloseScope
		if err := json.Unmarshal(scopeRaw, &scope); err != nil {
			return fmt.Errorf("store: failed to unmarshal scope: %w", err)
		}

		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, scope.Key()); err != nil {
			return fmt.Errorf("store: locking scope failed: %w", err)
		}

		// D83: a run of the same scope that completed after the held run describes the scope now; the hold is
		// superseded and closes nothing.
		var newer bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM ingest_run_scope s JOIN ingest_run r ON r.id = s.ingest_run_id
				WHERE s.tenant_id = $1 AND s.scan_source_id = $2 AND s.scanner_family = $3 AND s.asset_id = $4 AND s.track = $5
				  AND r.id <> $6 AND r.status IN ('completed', 'completed_with_errors')
				  AND r.created_at > (SELECT created_at FROM ingest_run WHERE id = $6))`,
			tenantID, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track, ingestRunID).Scan(&newer); err != nil {
			return err
		}
		if newer {
			return errSupersededCommit // nothing in this transaction is kept; the mark is written below
		}

		for _, fid := range findingIDs {
			var state domain.FindingState
			err := tx.QueryRow(ctx, `SELECT state FROM finding WHERE tenant_id = $1 AND id = $2`, tenantID, fid).Scan(&state)
			if err != nil {
				continue // finding may have been deleted or doesn't exist
			}
			if state != domain.StateOpen && state != domain.StateUnderInvestigation && state != domain.StateAffected {
				continue // not active disposition
			}

			// Check if finding came back in a later run:
			// If any present occurrence exists from a run created AFTER the held run, it came back!
			var cameBackCount int
			checkQuery := `
				SELECT count(*)
				FROM occurrence o
				JOIN ingest_run r ON o.ingest_run_id = r.id
				WHERE o.tenant_id = $1 AND o.finding_id = $2
				  AND o.scan_source_id = $3 AND o.scanner_family = $4
				  AND o.asset_id = $5 AND o.track = $6
				  AND o.present = true
				  AND r.created_at > (SELECT created_at FROM ingest_run WHERE id = $7)`
			if err := tx.QueryRow(ctx, checkQuery, tenantID, fid, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track, ingestRunID).Scan(&cameBackCount); err != nil {
				return err
			}
			if cameBackCount > 0 {
				continue // finding came back between held run and confirmation: do not close!
			}

			// Finding is still absent: mark occurrences not present
			_, err = tx.Exec(ctx, `
				UPDATE occurrence
				SET present = false
				WHERE tenant_id = $1 AND finding_id = $2
				  AND scan_source_id = $3 AND scanner_family = $4
				  AND asset_id = $5 AND track = $6`,
				tenantID, fid, scope.ScanSourceID, scope.ScannerFamily, scope.AssetID, scope.Track)
			if err != nil {
				return err
			}

			// D13: a finding stays open while another source still reports it; only its occurrences in this scope
			// stop being present.
			var stillReported bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM occurrence WHERE tenant_id = $1 AND finding_id = $2 AND present)`,
				tenantID, fid).Scan(&stillReported); err != nil {
				return err
			}
			if stillReported {
				continue
			}

			// Close finding
			resFixed := domain.ResolutionFixed
			_, err = tx.Exec(ctx, `
				UPDATE finding
				SET previous_state = state,
				    state = $3,
				    detection = $4,
				    resolution = $5,
				    resolved_at = $6,
				    version = version + 1
				WHERE tenant_id = $1 AND id = $2`,
				tenantID, fid, domain.StateFixed, domain.DetectionAbsent, resFixed, now)
			if err != nil {
				return err
			}

			// Record finding event
			eventID := domain.NewID()
			_, err = tx.Exec(ctx, `
				INSERT INTO finding_event (id, tenant_id, finding_id, at, actor, type, note)
				VALUES ($1, $2, $3, $4, $5, 'closed_by_rescan', $6)`,
				eventID, tenantID, fid, now, decidedBy, "confirmed held close "+id.String())
			if err != nil {
				return err
			}
			closedCount++
		}

		// Mark held close confirmed
		_, err := tx.Exec(ctx, `
			UPDATE held_close
			SET decision = $3, decided_by = $4, decided_at = $5
			WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, domain.HeldCloseDecisionConfirmed, decidedBy, now)
		return err
	})
	if errors.Is(err, errSupersededCommit) {
		if derr := s.DecideHeldClose(ctx, tenantID, id, domain.HeldCloseDecisionSuperseded, decidedBy); derr != nil {
			return 0, derr
		}
		return 0, ErrHeldCloseSuperseded
	}
	return closedCount, err
}

// errSupersededCommit carries "superseded" out of the transaction, which then rolls back; the mark is written in
// its own transaction by DecideHeldClose.
var errSupersededCommit = errors.New("superseded")
