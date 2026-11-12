package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// Notifications keeps the in-app messages and the one-time warnings that feed them (docs/16 D45). Only the
// PostgreSQL store implements it; callers ask with a type assertion, like Aggregator.
type Notifications interface {
	CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error
	// ListNotifications returns the newest first, each marked unread for this user, and the unread count.
	ListNotifications(ctx context.Context, tenantID uuid.UUID, user string, limit int) ([]domain.Notification, int, error)
	MarkNotificationsRead(ctx context.Context, tenantID uuid.UUID, user string, at time.Time) error
	// WarnSLADueSoon marks the findings whose deadline falls within `within` and returns them: each is warned once.
	WarnSLADueSoon(ctx context.Context, tenantID uuid.UUID, now time.Time, within time.Duration) ([]domain.DueSoon, error)
	// WarnExpiringAcceptances marks the approved acceptances that end within 14 days (then within 1 day) and
	// returns them: each threshold is announced once.
	WarnExpiringAcceptances(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]domain.ExpiringAcceptance, error)
}

func (s *PostgresStore) CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error {
	if n.ID == uuid.Nil {
		n.ID = domain.NewID()
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification (id, tenant_id, kind, title, body, link, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			n.ID, tenantID, n.Kind, n.Title, n.Body, n.Link, n.CreatedAt)
		return err
	})
}

func (s *PostgresStore) ListNotifications(ctx context.Context, tenantID uuid.UUID, user string, limit int) ([]domain.Notification, int, error) {
	out := []domain.Notification{}
	unread := 0
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT n.id, n.kind, n.title, n.body, n.link, n.created_at,
			       n.created_at > coalesce((SELECT read_at FROM notification_marker WHERE tenant_id = $1 AND user_ref = $2), '-infinity')
			FROM notification n WHERE n.tenant_id = $1 ORDER BY n.created_at DESC, n.id LIMIT $3`, tenantID, user, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n domain.Notification
			if err := rows.Scan(&n.ID, &n.Kind, &n.Title, &n.Body, &n.Link, &n.CreatedAt, &n.Unread); err != nil {
				return err
			}
			out = append(out, n)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// The count is of all unread, not only of the page returned.
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification WHERE tenant_id = $1
			AND created_at > coalesce((SELECT read_at FROM notification_marker WHERE tenant_id = $1 AND user_ref = $2), '-infinity')`,
			tenantID, user).Scan(&unread)
	})
	return out, unread, err
}

func (s *PostgresStore) MarkNotificationsRead(ctx context.Context, tenantID uuid.UUID, user string, at time.Time) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_marker (tenant_id, user_ref, read_at) VALUES ($1,$2,$3)
			ON CONFLICT (tenant_id, user_ref) DO UPDATE SET read_at = GREATEST(notification_marker.read_at, EXCLUDED.read_at)`, tenantID, user, at)
		return err
	})
}

func (s *PostgresStore) WarnSLADueSoon(ctx context.Context, tenantID uuid.UUID, now time.Time, within time.Duration) ([]domain.DueSoon, error) {
	var out []domain.DueSoon
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE finding SET sla_warned_at = $2
			WHERE tenant_id = $1 AND state IN `+activeStates+`
			  AND sla_due_date IS NOT NULL AND sla_due_date > $2 AND sla_due_date <= $2 + make_interval(secs => $3)
			  AND sla_breached_at IS NULL AND sla_paused_at IS NULL AND sla_warned_at IS NULL
			RETURNING id, title, coalesce(risk_band, ''), sla_due_date`, tenantID, now, within.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d domain.DueSoon
			if err := rows.Scan(&d.ID, &d.Title, &d.Band, &d.Due); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) WarnExpiringAcceptances(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]domain.ExpiringAcceptance, error) {
	var out []domain.ExpiringAcceptance
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE risk_acceptance ra SET expiry_warned_days =
				CASE WHEN ra.expires_at <= $2 + interval '1 day' THEN 1 ELSE 14 END
			WHERE ra.tenant_id = $1 AND ra.status = 'approved' AND ra.expires_at > $2 AND ra.expires_at <= $2 + interval '14 days'
			  AND (ra.expiry_warned_days IS NULL
			       OR ra.expiry_warned_days > CASE WHEN ra.expires_at <= $2 + interval '1 day' THEN 1 ELSE 14 END)
			RETURNING ra.id, ra.justification, ra.owner, ra.expires_at, ra.expiry_warned_days,
			          (SELECT count(*) FROM risk_acceptance_finding f WHERE f.risk_acceptance_id = ra.id)`, tenantID, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.ExpiringAcceptance
			if err := rows.Scan(&e.ID, &e.Justification, &e.Owner, &e.ExpiresAt, &e.DaysLeft, &e.Findings); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
