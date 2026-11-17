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
	// WarnExpiringAttestations does the same for the current "passed" attestation of each manual control (D123).
	// The message is written inside the same transaction as the marker (build makes it from what was found), so a marker
	// never exists without its message: a reminder is not lost between the two, and the one returned is to be routed.
	WarnExpiringAttestations(ctx context.Context, tenantID uuid.UUID, now time.Time, build func([]domain.ExpiringAttestation) *domain.Notification) ([]domain.ExpiringAttestation, *domain.Notification, error)
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

// WarnExpiringAttestations announces the attestations that end within 14 days, then within 1 day, once each. Only the
// current one of a control counts (the newest for that control and application): a superseded one ending is no news,
// and one that says "failed" has nothing to renew.
func (s *PostgresStore) WarnExpiringAttestations(ctx context.Context, tenantID uuid.UUID, now time.Time, build func([]domain.ExpiringAttestation) *domain.Notification) ([]domain.ExpiringAttestation, *domain.Notification, error) {
	var out []domain.ExpiringAttestation
	var note *domain.Notification
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH cur AS (
				SELECT DISTINCT ON (framework_id, control_id, application_id)
				       id, tenant_id, framework_id, control_id, application_id, status, owner, attested_by, expires_at
				FROM compliance_attestation WHERE tenant_id = $1
				ORDER BY framework_id, control_id, application_id, attested_at DESC, id
			), due AS (
				SELECT id, framework_id, control_id, application_id, owner, attested_by, expires_at,
				       CASE WHEN expires_at <= $2::timestamptz + interval '1 day' THEN 1 ELSE 14 END AS d
				FROM cur WHERE status = 'passed' AND expires_at > $2 AND expires_at <= $2::timestamptz + interval '14 days'
				  AND NOT `+coveredByTenant("cur")+`
			), ins AS (
				INSERT INTO compliance_attestation_warning (attestation_id, tenant_id, days)
				SELECT id, $1, d FROM due
				ON CONFLICT (attestation_id) DO UPDATE SET days = EXCLUDED.days, warned_at = NOW()
				WHERE compliance_attestation_warning.days > EXCLUDED.days
				RETURNING attestation_id, days
			)
			SELECT due.framework_id, due.control_id, coalesce(a.name, ''), CASE WHEN due.owner <> '' THEN due.owner ELSE due.attested_by END,
			       due.expires_at, ins.days
			FROM ins JOIN due ON due.id = ins.attestation_id LEFT JOIN application a ON a.id = due.application_id
			ORDER BY due.expires_at, due.control_id`, tenantID, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.ExpiringAttestation
			if err := rows.Scan(&e.FrameworkID, &e.ControlID, &e.Application, &e.Owner, &e.ExpiresAt, &e.DaysLeft); err != nil {
				return err
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		if build != nil && len(out) > 0 {
			note = build(out)
			if note.ID == uuid.Nil {
				note.ID = domain.NewID()
			}
			if note.CreatedAt.IsZero() {
				note.CreatedAt = now
			}
			_, err := tx.Exec(ctx, `INSERT INTO notification (id, tenant_id, kind, title, body, link, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				note.ID, tenantID, note.Kind, note.Title, note.Body, note.Link, note.CreatedAt)
			return err
		}
		return nil
	})
	return out, note, err
}
