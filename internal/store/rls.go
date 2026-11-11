package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// SetTenantContext sets the PostgreSQL session configuration variable 'app.tenant_id'
// for the duration of the current transaction (normative D4).
func SetTenantContext(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	if tenantID == domain.NilID {
		return domain.ErrInvalidTenantID
	}
	// is_local=true ensures the setting is scoped strictly to the current transaction
	query := "SELECT set_config('app.tenant_id', $1, true)"
	_, err := tx.ExecContext(ctx, query, tenantID.String())
	if err != nil {
		return fmt.Errorf("store: failed to set transaction tenant context: %w", err)
	}
	return nil
}
