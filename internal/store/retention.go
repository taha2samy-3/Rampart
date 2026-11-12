package store

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Retention (docs/16 D53). Tenant data is removed one tenant at a time, as the application role under row-level
// security, in batches of retentionBatch rows per transaction so a large backlog never holds long locks. The two
// partitioned logs (finding_event, audit_event) leave a month at a time, dropped by the owner.

const retentionBatch = 5000

// purgeInBatches runs a DELETE that removes at most retentionBatch rows (its last argument is the limit) until it
// removes fewer, each batch in its own tenant transaction.
func (s *PostgresStore) purgeInBatches(ctx context.Context, tenantID uuid.UUID, sql string, args ...any) (int64, error) {
	var total int64
	args = append(args, retentionBatch)
	for {
		var n int64
		err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		total += n
		if err != nil || n < retentionBatch {
			return total, err
		}
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

// PurgeAbsentOccurrences deletes occurrences no scanner has reported since before cutoff (D12). Present
// occurrences are never touched, so a finding's occurrence count and detection do not change.
func (s *PostgresStore) PurgeAbsentOccurrences(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error) {
	return s.purgeInBatches(ctx, tenantID, `
		DELETE FROM occurrence WHERE id IN (
			SELECT id FROM occurrence
			WHERE tenant_id = $1 AND NOT present AND last_seen < $2
			LIMIT $3)`, tenantID, cutoff)
}

// PurgeResolvedFindings deletes findings fixed before cutoff that no scanner reports any more, with their
// occurrences and timeline (ON DELETE CASCADE). A finding another finding names as the one it duplicates is kept,
// so that link never points nowhere. The rows are locked, so a merge that is reporting one again waits, and
// the next scan creates it anew.
func (s *PostgresStore) PurgeResolvedFindings(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error) {
	return s.purgeInBatches(ctx, tenantID, `
		DELETE FROM finding WHERE id IN (
			SELECT f.id FROM finding f
			WHERE f.tenant_id = $1 AND f.state = 'fixed' AND f.resolved_at < $2
			  AND NOT EXISTS (SELECT 1 FROM occurrence o WHERE o.tenant_id = f.tenant_id AND o.finding_id = f.id AND o.present)
			  AND NOT EXISTS (SELECT 1 FROM finding d WHERE d.tenant_id = f.tenant_id AND d.duplicate_of_id = f.id)
			LIMIT $3
			FOR UPDATE OF f SKIP LOCKED)`, tenantID, cutoff)
}

// PurgeRunResults deletes what runs older than cutoff found new or fixed (D10: kept 30 days for the CI gate).
func (s *PostgresStore) PurgeRunResults(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error) {
	return s.purgeInBatches(ctx, tenantID, `
		DELETE FROM ingest_run_result WHERE id IN (
			SELECT id FROM ingest_run_result WHERE tenant_id = $1 AND created_at < $2 LIMIT $3)`, tenantID, cutoff)
}

// PurgeKeyAliases deletes old finding keys recorded by the RekeyJob before cutoff. D11 keeps an old key
// resolvable for one retention period, the occurrence one: after it, no scanner still reporting the old
// identifier is expected.
func (s *PostgresStore) PurgeKeyAliases(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error) {
	return s.purgeInBatches(ctx, tenantID, `
		DELETE FROM finding_key_alias WHERE (tenant_id, old_key) IN (
			SELECT tenant_id, old_key FROM finding_key_alias WHERE tenant_id = $1 AND created_at < $2 LIMIT $3)`, tenantID, cutoff)
}

// ExpiredReport is a raw report whose time is up.
type ExpiredReport struct {
	UploadID  uuid.UUID
	ObjectRef string
	Abandoned bool // created and never completed: no run read it
}

// ExpiredReports lists, oldest first, raw reports to remove:
//   - an upload created before abandonedBefore that was never completed;
//   - the report of a finished run that found secrets, or that failed (what it held is unknown), finished
//     before secretBefore;
//   - any other finished run's report, finished before rawBefore.
//
// A zero time turns its rule off. A run still in progress keeps its report.
func (s *PostgresStore) ExpiredReports(ctx context.Context, tenantID uuid.UUID, abandonedBefore, secretBefore, rawBefore time.Time, limit int) ([]ExpiredReport, error) {
	var out []ExpiredReport
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id, u.object_ref, u.status = 'created'
			FROM upload u
			WHERE u.tenant_id = $1 AND u.status <> 'purged' AND (
			      (u.status = 'created' AND u.created_at < $2)
			   OR EXISTS (
			      SELECT 1 FROM ingest_run r
			      WHERE r.tenant_id = u.tenant_id AND r.upload_id = u.id AND r.finished_at IS NOT NULL
			        AND (   ($3::timestamptz IS NOT NULL AND (r.holds_secrets OR r.status = 'failed') AND r.finished_at < $3)
			             OR ($4::timestamptz IS NOT NULL AND r.finished_at < $4))))
			ORDER BY u.created_at
			LIMIT $5`, tenantID, nullTime(abandonedBefore), nullTime(secretBefore), nullTime(rawBefore), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ExpiredReport
			if err := rows.Scan(&r.UploadID, &r.ObjectRef, &r.Abandoned); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// MarkReportPurged records that the object of an upload is gone: the upload becomes "purged" (it can no longer
// be completed) and its runs say when, so the run page stops offering the download.
func (s *PostgresStore) MarkReportPurged(ctx context.Context, tenantID, uploadID uuid.UUID, at time.Time) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE upload SET status = 'purged' WHERE tenant_id = $1 AND id = $2`, tenantID, uploadID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE ingest_run SET report_purged_at = $3 WHERE tenant_id = $1 AND upload_id = $2 AND report_purged_at IS NULL`,
			tenantID, uploadID, at)
		return err
	})
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// partitionName matches the monthly partitions MaintainPartitions creates: <table>_y2026_m11.
var partitionName = regexp.MustCompile(`_y(\d{4})_m(\d{2})$`)

// DroppedPartitions says what DropExpiredPartitions removed.
type DroppedPartitions struct {
	Partitions  []string // whole months dropped
	DefaultRows int64    // old rows removed from the default partitions
}

// DropExpiredPartitions drops the monthly partitions of finding_event older than eventsBefore and of
// audit_event older than auditBefore, a month only once all of it is older, and deletes old rows that landed in
// the default partitions. It needs the owner role: the application and system roles cannot change the audit log
// (D46), and only the owner may drop a table. A zero time keeps that log for ever.
func DropExpiredPartitions(ctx context.Context, pool *pgxpool.Pool, eventsBefore, auditBefore time.Time) (DroppedPartitions, error) {
	var out DroppedPartitions
	if pool == nil {
		return out, fmt.Errorf("store: database pool is required for partition retention")
	}
	for _, t := range []struct {
		parent string
		before time.Time
	}{{"finding_event", eventsBefore}, {"audit_event", auditBefore}} {
		if t.before.IsZero() {
			continue
		}
		rows, err := pool.Query(ctx, `
			SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
			WHERE i.inhparent = $1::regclass ORDER BY c.relname`, t.parent)
		if err != nil {
			return out, err
		}
		var parts []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return out, err
			}
			parts = append(parts, name)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
		for _, name := range parts {
			m := partitionName.FindStringSubmatch(name)
			if m == nil || name != fmt.Sprintf("%s_y%s_m%s", t.parent, m[1], m[2]) {
				continue // the default partition, or something that is not ours
			}
			year, _ := strconv.Atoi(m[1])
			month, _ := strconv.Atoi(m[2])
			end := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
			if end.After(t.before) {
				continue // some of the month is still inside the retention period
			}
			if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, pgx.Identifier{name}.Sanitize())); err != nil {
				return out, fmt.Errorf("store: dropping partition %s: %w", name, err)
			}
			out.Partitions = append(out.Partitions, name)
		}
		tag, err := pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE at < $1`, pgx.Identifier{t.parent + "_default"}.Sanitize()), t.before)
		if err != nil {
			return out, fmt.Errorf("store: trimming %s_default: %w", t.parent, err)
		}
		out.DefaultRows += tag.RowsAffected()
	}
	return out, nil
}
