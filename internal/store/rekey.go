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

// RekeyOutcome says what happened to one finding.
type RekeyOutcome string

const (
	RekeyRenamed RekeyOutcome = "renamed" // the finding took the new key
	RekeyMerged  RekeyOutcome = "merged"  // a finding with the new key existed: the two became one
	RekeyStale   RekeyOutcome = "stale"   // the finding changed since it was read: leave it for the next pass
)

// Rekeyer re-keys findings whose vulnerability identifier became an alias of a CVE (docs/16 D11, D50).
// Only the PostgreSQL store implements it.
type Rekeyer interface {
	// ListRekeyCandidates pages through the software-composition findings whose identifier is not a CVE: the only
	// ones an alias can move to a CVE.
	ListRekeyCandidates(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error)
	// RekeyFinding gives the finding newKey and newVuln. If another finding already has newKey the two are merged.
	RekeyFinding(ctx context.Context, tenantID, id uuid.UUID, oldKey, newKey, newVuln string) (RekeyOutcome, error)
}

func (s *PostgresStore) ListRekeyCandidates(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error) {
	var out []*domain.Finding
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM finding
			WHERE tenant_id = $1 AND id > $2 AND category = 'sca' AND vulnerability_id IS NOT NULL AND vulnerability_id NOT LIKE 'CVE-%'
			ORDER BY id LIMIT $3`, tenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// decided says a person has made a decision on the finding (anything but the two states a scan sets).
func decided(state string) bool { return state != "open" && state != "under_investigation" }

type rekeyRow struct {
	id        uuid.UUID
	key       string
	state     string
	firstSeen time.Time
}

func (s *PostgresStore) RekeyFinding(ctx context.Context, tenantID, id uuid.UUID, oldKey, newKey, newVuln string) (RekeyOutcome, error) {
	outcome := RekeyStale
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		read := func(where string, arg any) (*rekeyRow, error) {
			r := &rekeyRow{}
			err := tx.QueryRow(ctx, `SELECT id, finding_key, state, first_seen FROM finding WHERE tenant_id = $1 AND `+where+` FOR UPDATE`, tenantID, arg).Scan(&r.id, &r.key, &r.state, &r.firstSeen)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			return r, err
		}
		f, err := read("id = $2", id)
		if err != nil || f == nil || f.key != oldKey {
			return err // gone, or already re-keyed by another pass
		}
		g, err := read("finding_key = $2", newKey)
		if err != nil {
			return err
		}
		event := func(findingID uuid.UUID, typ string, from, to any, note string) error {
			fj, _ := json.Marshal(from)
			tj, _ := json.Marshal(to)
			_, err := tx.Exec(ctx, `INSERT INTO finding_event (id, tenant_id, finding_id, at, actor, type, "from", "to", note) VALUES ($1,$2,$3,NOW(),'system:rekey',$4,$5,$6,$7)`,
				domain.NewID(), tenantID, findingID, typ, fj, tj, note)
			return err
		}
		alias := func(survivor uuid.UUID) error {
			_, err := tx.Exec(ctx, `INSERT INTO finding_key_alias (tenant_id, old_key, new_key, finding_id) VALUES ($1,$2,$3,$4)
				ON CONFLICT (tenant_id, old_key) DO UPDATE SET new_key = EXCLUDED.new_key, finding_id = EXCLUDED.finding_id`, tenantID, oldKey, newKey, survivor)
			return err
		}
		if g == nil || g.id == f.id {
			if _, err := tx.Exec(ctx, `UPDATE finding SET finding_key = $3, vulnerability_id = $4, version = version + 1, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tenantID, f.id, newKey, newVuln); err != nil {
				return err
			}
			if err := alias(f.id); err != nil {
				return err
			}
			outcome = RekeyRenamed
			return event(f.id, "rekeyed", map[string]string{"vulnerability_id": oldKey}, map[string]string{"vulnerability_id": newVuln}, "The identifier became an alias of "+newVuln+"; the finding is now keyed by it.")
		}

		// Two findings for one flaw. A decision a person made outranks a scan's guess; otherwise the older one
		// wins (docs/16 D11). Everything that belongs to the other one moves to the winner.
		survivor, loser := g, f
		switch fd, gd := decided(f.state), decided(g.state); {
		case fd && !gd:
			survivor, loser = f, g
		case fd == gd && f.firstSeen.Before(g.firstSeen):
			survivor, loser = f, g
		}
		moves := []string{
			`UPDATE occurrence o SET finding_id = $2 WHERE tenant_id = $1 AND finding_id = $3
			   AND NOT EXISTS (SELECT 1 FROM occurrence x WHERE x.tenant_id = $1 AND x.finding_id = $2 AND x.scan_source_id IS NOT DISTINCT FROM o.scan_source_id AND x.occurrence_key = o.occurrence_key)`,
			`UPDATE finding_event SET finding_id = $2 WHERE tenant_id = $1 AND finding_id = $3`,
			`UPDATE risk_acceptance_finding r SET finding_id = $2 WHERE tenant_id = $1 AND finding_id = $3
			   AND NOT EXISTS (SELECT 1 FROM risk_acceptance_finding x WHERE x.risk_acceptance_id = r.risk_acceptance_id AND x.finding_id = $2)`,
			`DELETE FROM risk_acceptance_finding WHERE tenant_id = $1 AND finding_id = $3 AND $2::uuid IS NOT NULL`,
			`UPDATE finding_key_alias SET finding_id = $2 WHERE tenant_id = $1 AND finding_id = $3`,
			`UPDATE finding SET duplicate_of_id = $2 WHERE tenant_id = $1 AND duplicate_of_id = $3`,
		}
		for _, q := range moves {
			if _, err := tx.Exec(ctx, q, tenantID, survivor.id, loser.id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE finding SET
				tags = (SELECT coalesce(array_agg(DISTINCT t ORDER BY t), '{}') FROM unnest(tags || (SELECT tags FROM finding WHERE tenant_id = $1 AND id = $3)) t),
				first_seen = LEAST(first_seen, (SELECT first_seen FROM finding WHERE tenant_id = $1 AND id = $3)),
				last_seen = GREATEST(last_seen, (SELECT last_seen FROM finding WHERE tenant_id = $1 AND id = $3))
			WHERE tenant_id = $1 AND id = $2`, tenantID, survivor.id, loser.id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM finding WHERE tenant_id = $1 AND id = $2`, tenantID, loser.id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE finding SET finding_key = $3, vulnerability_id = $4,
				occurrence_count = (SELECT count(*) FROM occurrence WHERE tenant_id = $1 AND finding_id = $2 AND present),
				version = version + 1, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`, tenantID, survivor.id, newKey, newVuln); err != nil {
			return err
		}
		if err := alias(survivor.id); err != nil {
			return err
		}
		outcome = RekeyMerged
		return event(survivor.id, "merged_duplicate", map[string]string{"merged_finding": loser.id.String()}, nil,
			"Two findings for the same flaw (an identifier and its CVE alias) became one: the one a person decided about, or else the older.")
	})
	return outcome, err
}

// RunErrors keeps the records of a report that could not be read. Only the PostgreSQL store implements it.
type RunErrors interface {
	// ReplaceRunErrors stores the first records the run could not read, replacing what a retried job left.
	ReplaceRunErrors(ctx context.Context, tenantID, runID uuid.UUID, errs []domain.RecordError) error
	ListRunErrors(ctx context.Context, tenantID, runID uuid.UUID) ([]domain.RecordError, error)
}

func (s *PostgresStore) ReplaceRunErrors(ctx context.Context, tenantID, runID uuid.UUID, errs []domain.RecordError) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM ingest_run_error WHERE tenant_id = $1 AND ingest_run_id = $2`, tenantID, runID); err != nil {
			return err
		}
		for i, e := range errs {
			if _, err := tx.Exec(ctx, `INSERT INTO ingest_run_error (tenant_id, ingest_run_id, n, location, message) VALUES ($1,$2,$3,$4,$5)`,
				tenantID, runID, i+1, e.Where, e.Message); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *PostgresStore) ListRunErrors(ctx context.Context, tenantID, runID uuid.UUID) ([]domain.RecordError, error) {
	out := []domain.RecordError{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT location, message FROM ingest_run_error WHERE tenant_id = $1 AND ingest_run_id = $2 ORDER BY n`, tenantID, runID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.RecordError
			if err := rows.Scan(&e.Where, &e.Message); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
