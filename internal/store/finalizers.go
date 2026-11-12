package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrSourceDisabled is returned for an upload to a scan source whose resource was deleted (docs/16 D49).
var ErrSourceDisabled = errors.New("store: the scan source is disabled")

// OrphanApplication implements apply.Finalizer: the application and its findings stay, and it is editable in
// the UI from now on.
func (s *PostgresStore) OrphanApplication(ctx context.Context, tenantID uuid.UUID, slug string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE application SET managed_by = 'none' WHERE tenant_id = $1 AND slug = $2 AND managed_by = 'crd'`, tenantID, slug)
		return err
	})
}

// DisableScanSource implements apply.Finalizer.
func (s *PostgresStore) DisableScanSource(ctx context.Context, tenantID uuid.UUID, name string) (int, error) {
	revoked := 0
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `UPDATE scan_source SET disabled_at = coalesce(disabled_at, NOW()) WHERE tenant_id = $1 AND name = $2 RETURNING id`, tenantID, name).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // never reconciled, or already gone: nothing to disable
		}
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE api_token SET revoked_at = NOW() WHERE tenant_id = $1 AND scan_source_id = $2 AND revoked_at IS NULL`, tenantID, id)
		if err != nil {
			return err
		}
		revoked = int(tag.RowsAffected())
		// The material the operator copied for this source (its keys are scansource:<name>:<key>).
		_, err = tx.Exec(ctx, `DELETE FROM secret_material WHERE tenant_id = $1 AND key LIKE $2 ESCAPE '\'`, tenantID, likeEscape("scansource:"+name+":")+"%")
		return err
	})
	return revoked, err
}

func likeEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '%' || c == '_' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// DeleteSLAPolicy implements apply.Finalizer. The tenant's due dates are recomputed: the remaining policy, or
// the built-in one, now applies.
func (s *PostgresStore) DeleteSLAPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error {
	return s.deletePolicy(ctx, tenantID, "sla", namespace, name)
}

// DeleteRiskPolicy implements apply.Finalizer: the tenant is re-scored against what is left (D62).
func (s *PostgresStore) DeleteRiskPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error {
	return s.deletePolicy(ctx, tenantID, "risk", namespace, name)
}

func (s *PostgresStore) deletePolicy(ctx context.Context, tenantID uuid.UUID, kind, namespace, name string) error {
	// The flag that asks for a recompute lives on policy rows, and the row that carried it is going. A tombstone
	// row (no applied spec, so it is never a policy in force) carries it instead; the sweep clears the flag.
	return s.withSystemTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM policy_object WHERE tenant_id = $1 AND kind = $4 AND namespace = $2 AND name = $3`, tenantID, namespace, name, kind); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO policy_object (id, tenant_id, kind, namespace, name, spec, applied_spec, compiled_ok, generation, recompute_needed)
			SELECT gen_random_uuid(), $1, $2, '_deleted', 'tombstone', '{}', NULL, TRUE, 0, TRUE
			ON CONFLICT (tenant_id, kind, namespace, name) DO UPDATE SET recompute_needed = TRUE, updated_at = NOW()`, tenantID, kind)
		return err
	})
}

// TenantHasData implements apply.Finalizer.
func (s *PostgresStore) TenantHasData(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var has bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM application WHERE tenant_id = $1)
		OR EXISTS (SELECT 1 FROM asset WHERE tenant_id = $1)
		OR EXISTS (SELECT 1 FROM finding WHERE tenant_id = $1)
		OR EXISTS (SELECT 1 FROM ingest_run WHERE tenant_id = $1)`, tenantID).Scan(&has)
	return has, err
}

// PurgeTenant implements apply.Finalizer. Every table that belongs to a tenant references it with ON DELETE
// CASCADE, so one delete removes everything.
func (s *PostgresStore) PurgeTenant(ctx context.Context, tenantID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM tenant WHERE id = $1`, tenantID)
	return err
}

func (s *PostgresStore) withSystemTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
