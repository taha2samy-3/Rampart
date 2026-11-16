package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// PendingGroupTicket is a group ticket the sweeper still owes a tracker (docs/16 D90).
type PendingGroupTicket struct {
	TenantID uuid.UUID
	GroupID  uuid.UUID
	Attempts int
}

// GroupTicketOutbox is the group half of the ticket outbox, and the lookup that keeps one ticket per correlation
// group (D90). Only the PostgreSQL store implements it; the sweeper checks for it.
type GroupTicketOutbox interface {
	// ListPendingGroupTickets reads across tenants: it needs rampart_system.
	ListPendingGroupTickets(ctx context.Context, now time.Time, limit int) ([]PendingGroupTicket, error)
	// CompleteGroupTicket records the ticket and links it to every member of the group.
	CompleteGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, connector, ticketRef, url string) error
	// RetryGroupTicket schedules another attempt, or gives up (status failed) when giveUp is set.
	RetryGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, errMsg string, next time.Time, giveUp bool) error
	// CorrelatedTicket returns an open ticket on this connector that already tracks another finding with the same
	// correlation key in the same application; empty when there is none.
	CorrelatedTicket(ctx context.Context, tenantID, findingID uuid.UUID, connector string) (ref, url string, err error)
}

func (s *PostgresStore) ListPendingGroupTickets(ctx context.Context, now time.Time, limit int) ([]PendingGroupTicket, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id, id, ticket_attempts FROM finding_group
		WHERE ticket_status = 'reserved' AND ticket_next_at <= $1 ORDER BY ticket_next_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingGroupTicket
	for rows.Next() {
		var p PendingGroupTicket
		if err := rows.Scan(&p.TenantID, &p.GroupID, &p.Attempts); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CompleteGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, connector, ticketRef, url string) error {
	if connector == "" {
		connector = "tracker"
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ticketID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO ticket (id, tenant_id, connector, external_ref, url, state, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'open', NOW(), NOW())
			ON CONFLICT (tenant_id, connector, external_ref) DO UPDATE SET url = EXCLUDED.url, updated_at = NOW()
			RETURNING id`, ticketID, tenantID, connector, ticketRef, url).Scan(&ticketID); err != nil {
			return err
		}
		// Every member that is still a finding is linked; a member whose finding was deleted is skipped.
		if _, err := tx.Exec(ctx, `INSERT INTO ticket_finding (tenant_id, ticket_id, finding_id)
			SELECT m.tenant_id, $3, m.finding_id FROM finding_group_member m
			JOIN finding f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			WHERE m.tenant_id = $1 AND m.group_id = $2
			ON CONFLICT (tenant_id, ticket_id, finding_id) DO NOTHING`, tenantID, groupID, ticketID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE finding_group SET ticket_status = 'done', ticket_id = $3, ticket_error = NULL,
			ticket_next_at = NULL, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tenantID, groupID, ticketID)
		return err
	})
}

func (s *PostgresStore) RetryGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, errMsg string, next time.Time, giveUp bool) error {
	status := "reserved"
	if giveUp {
		status = "failed"
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE finding_group SET ticket_status = $3, ticket_attempts = ticket_attempts + 1,
			ticket_error = $4, ticket_next_at = $5, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
			tenantID, groupID, status, errMsg, next)
		return err
	})
}

func (s *PostgresStore) CorrelatedTicket(ctx context.Context, tenantID, findingID uuid.UUID, connector string) (string, string, error) {
	var ref, url string
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT t.external_ref, t.url FROM finding f
			JOIN finding o ON o.tenant_id = f.tenant_id AND o.application_id = f.application_id
				AND o.correlation_key = f.correlation_key AND o.id <> f.id
			JOIN ticket_finding tf ON tf.tenant_id = o.tenant_id AND tf.finding_id = o.id
			JOIN ticket t ON t.tenant_id = tf.tenant_id AND t.id = tf.ticket_id
			WHERE f.tenant_id = $1 AND f.id = $2 AND f.correlation_key IS NOT NULL
			  AND t.connector = $3 AND t.state = 'open'
			ORDER BY t.created_at LIMIT 1`, tenantID, findingID, connector).Scan(&ref, &url)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	})
	return ref, url, err
}
