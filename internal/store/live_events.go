package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// LiveEventSource is what a query-api replica's live hub reads (docs/16 D91). It reads across tenants, so it is
// given the system store.
type LiveEventSource interface {
	ListLiveEvents(ctx context.Context, afterID int64, limit int) ([]domain.LiveEvent, error)
	MaxLiveEventID(ctx context.Context) (int64, error)
	PruneLiveEvents(ctx context.Context, before time.Time) (int64, error)
}

// LiveEventReplay reads one tenant's events after a Last-Event-ID, under that tenant's row-level security.
type LiveEventReplay interface {
	ListTenantLiveEvents(ctx context.Context, tenantID uuid.UUID, afterID int64, limit int) ([]domain.LiveEvent, error)
}

func scanLiveEvents(rows pgx.Rows) ([]domain.LiveEvent, error) {
	defer rows.Close()
	var out []domain.LiveEvent
	for rows.Next() {
		var e domain.LiveEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Topic, &e.ApplicationID, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListLiveEvents(ctx context.Context, afterID int64, limit int) ([]domain.LiveEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, topic, application_id, at FROM live_event
		WHERE id > $1 ORDER BY id LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, err
	}
	return scanLiveEvents(rows)
}

func (s *PostgresStore) MaxLiveEventID(ctx context.Context) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(id), 0) FROM live_event`).Scan(&id)
	return id, err
}

func (s *PostgresStore) PruneLiveEvents(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM live_event WHERE at < $1`, before)
	return tag.RowsAffected(), err
}

func (s *PostgresStore) ListTenantLiveEvents(ctx context.Context, tenantID uuid.UUID, afterID int64, limit int) ([]domain.LiveEvent, error) {
	var out []domain.LiveEvent
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, topic, application_id, at FROM live_event
			WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		out, err = scanLiveEvents(rows)
		return err
	})
	return out, err
}
