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

// PendingTicket is a ticket the outbox still owes a tracker.
type PendingTicket struct {
	TenantID  uuid.UUID
	FindingID uuid.UUID
	Attempts  int
	Reserved  time.Time
}

// Tickets defines CRUD and linking operations for external tickets (D70 B1).
type Tickets interface {
	CreateTicket(ctx context.Context, tenantID uuid.UUID, t *domain.Ticket) (*domain.Ticket, error)
	LinkFinding(ctx context.Context, tenantID, ticketID, findingID uuid.UUID) error
	TicketsOfFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.Ticket, error)
	FindingHasTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef string) (bool, error)
	SetTicketState(ctx context.Context, tenantID, ticketID uuid.UUID, state string) error
	CountTicketsCreatedSince(ctx context.Context, tenantID uuid.UUID, connector string, since time.Time) (int, error)
	RecordWebhookDelivery(ctx context.Context, tenantID uuid.UUID, connector, deliveryID string, expiresAt time.Time) (bool, error)
}

// TicketOutbox is the ledger of tickets to open (docs/16 D70). Only the PostgreSQL store implements it.
type TicketOutbox interface {
	// ListPendingTickets returns, across tenants, the reservations that are due. It reads across tenants: it needs rampart_system.
	ListPendingTickets(ctx context.Context, now time.Time, limit int) ([]PendingTicket, error)
	// CompleteTicket records the ticket that was opened.
	CompleteTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef, url string) error
	// RetryTicket schedules another attempt, or gives up (status failed) when giveUp is set.
	RetryTicket(ctx context.Context, tenantID, findingID uuid.UUID, errMsg string, next time.Time, giveUp bool) error
	// DeferTicket pushes the next attempt back without counting it (no tracker is configured yet).
	DeferTicket(ctx context.Context, tenantID, findingID uuid.UUID, next time.Time) error
	// SkipTicket closes a reservation that will not be acted on.
	SkipTicket(ctx context.Context, tenantID, findingID uuid.UUID, reason string) error
	// FindingHasTicket says whether a ticket with this reference was opened for the finding. It is what ties a ticket
	// that comes back in a webhook to a finding.
	FindingHasTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef string) (bool, error)
}

var ticketAction = domain.ActionCreateTicket

func (s *PostgresStore) ListPendingTickets(ctx context.Context, now time.Time, limit int) ([]PendingTicket, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id, finding_id, attempts, created_at FROM action_ledger
		WHERE action = $1 AND status = 'reserved' AND next_attempt_at <= $2 ORDER BY next_attempt_at LIMIT $3`, ticketAction, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingTicket
	for rows.Next() {
		var p PendingTicket
		if err := rows.Scan(&p.TenantID, &p.FindingID, &p.Attempts, &p.Reserved); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CompleteTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef, url string) error {
	res, _ := json.Marshal(map[string]string{"ticket_id": ticketRef, "url": url})
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		// 1. Insert/update ticket row (D70 B1)
		ticketID := domain.NewID()
		err := tx.QueryRow(ctx, `INSERT INTO ticket (id, tenant_id, connector, external_ref, url, state, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'open', NOW(), NOW())
			ON CONFLICT (tenant_id, connector, external_ref)
			DO UPDATE SET url = EXCLUDED.url, updated_at = NOW()
			RETURNING id`, ticketID, tenantID, "tracker", ticketRef, url).Scan(&ticketID)
		if err != nil {
			return err
		}

		// 2. Link finding to ticket
		_, err = tx.Exec(ctx, `INSERT INTO ticket_finding (tenant_id, ticket_id, finding_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, ticket_id, finding_id) DO NOTHING`, tenantID, ticketID, findingID)
		if err != nil {
			return err
		}

		// 3. Update action_ledger
		_, err = tx.Exec(ctx, `UPDATE action_ledger SET status = 'done', result = $4, last_error = NULL, updated_at = NOW()
			WHERE tenant_id = $1 AND finding_id = $2 AND action = $3`, tenantID, findingID, ticketAction, res)
		return err
	})
}

func (s *PostgresStore) CreateTicket(ctx context.Context, tenantID uuid.UUID, t *domain.Ticket) (*domain.Ticket, error) {
	if t == nil {
		return nil, errors.New("ticket is nil")
	}
	if t.ID == uuid.Nil {
		t.ID = domain.NewID()
	}
	if t.TenantID == uuid.Nil {
		t.TenantID = tenantID
	}
	if t.Connector == "" {
		t.Connector = "tracker"
	}
	if t.State == "" {
		t.State = "open"
	}
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	out := *t
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO ticket (id, tenant_id, connector, external_ref, url, state, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (tenant_id, connector, external_ref)
			DO UPDATE SET url = EXCLUDED.url, state = EXCLUDED.state, updated_at = NOW()
			RETURNING id, tenant_id, connector, external_ref, url, state, created_at, updated_at`,
			t.ID, tenantID, t.Connector, t.ExternalRef, t.URL, t.State, t.CreatedAt, t.UpdatedAt,
		).Scan(&out.ID, &out.TenantID, &out.Connector, &out.ExternalRef, &out.URL, &out.State, &out.CreatedAt, &out.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PostgresStore) LinkFinding(ctx context.Context, tenantID, ticketID, findingID uuid.UUID) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ticket_finding (tenant_id, ticket_id, finding_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, ticket_id, finding_id) DO NOTHING`,
			tenantID, ticketID, findingID)
		return err
	})
}

func (s *PostgresStore) TicketsOfFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.Ticket, error) {
	var out []*domain.Ticket
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT t.id, t.tenant_id, t.connector, t.external_ref, t.url, t.state, t.created_at, t.updated_at
			FROM ticket t
			JOIN ticket_finding tf ON tf.tenant_id = t.tenant_id AND tf.ticket_id = t.id
			WHERE tf.tenant_id = $1 AND tf.finding_id = $2
			ORDER BY t.created_at DESC`, tenantID, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t domain.Ticket
			if err := rows.Scan(&t.ID, &t.TenantID, &t.Connector, &t.ExternalRef, &t.URL, &t.State, &t.CreatedAt, &t.UpdatedAt); err != nil {
				return err
			}
			out = append(out, &t)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) SetTicketState(ctx context.Context, tenantID, ticketID uuid.UUID, state string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ticket SET state = $3, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`, tenantID, ticketID, state)
		return err
	})
}

func (s *PostgresStore) CountTicketsCreatedSince(ctx context.Context, tenantID uuid.UUID, connector string, since time.Time) (int, error) {
	var count int
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if connector == "" {
			return tx.QueryRow(ctx, `SELECT COUNT(*) FROM ticket WHERE tenant_id = $1 AND created_at >= $2`, tenantID, since).Scan(&count)
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM ticket WHERE tenant_id = $1 AND connector = $2 AND created_at >= $3`, tenantID, connector, since).Scan(&count)
	})
	return count, err
}

func (s *PostgresStore) RecordWebhookDelivery(ctx context.Context, tenantID uuid.UUID, connector, deliveryID string, expiresAt time.Time) (bool, error) {
	if deliveryID == "" {
		return true, nil
	}
	var recorded bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO webhook_delivery (tenant_id, connector, delivery_id, expires_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, connector, delivery_id) DO NOTHING`,
			tenantID, connector, deliveryID, expiresAt)
		if err != nil {
			return err
		}
		recorded = tag.RowsAffected() > 0
		return nil
	})
	return recorded, err
}

func (s *PostgresStore) RetryTicket(ctx context.Context, tenantID, findingID uuid.UUID, errMsg string, next time.Time, giveUp bool) error {
	status := "reserved"
	if giveUp {
		status = "failed"
	}
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE action_ledger SET status = $4, attempts = attempts + 1, next_attempt_at = $5, last_error = $6, updated_at = NOW()
			WHERE tenant_id = $1 AND finding_id = $2 AND action = $3`, tenantID, findingID, ticketAction, status, next, errMsg)
		return err
	})
}

func (s *PostgresStore) DeferTicket(ctx context.Context, tenantID, findingID uuid.UUID, next time.Time) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE action_ledger SET next_attempt_at = $4, updated_at = NOW()
			WHERE tenant_id = $1 AND finding_id = $2 AND action = $3 AND status = 'reserved'`, tenantID, findingID, ticketAction, next)
		return err
	})
}

func (s *PostgresStore) SkipTicket(ctx context.Context, tenantID, findingID uuid.UUID, reason string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE action_ledger SET status = 'skipped', last_error = $4, updated_at = NOW()
			WHERE tenant_id = $1 AND finding_id = $2 AND action = $3 AND status = 'reserved'`, tenantID, findingID, ticketAction, reason)
		return err
	})
}

func (s *PostgresStore) FindingHasTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef string) (bool, error) {
	if ticketRef == "" {
		return false, nil
	}
	var ok bool
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		// 1. Check ticket_finding joined with ticket (D70 B1)
		err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM ticket_finding tf
			JOIN ticket t ON t.tenant_id = tf.tenant_id AND t.id = tf.ticket_id
			WHERE tf.tenant_id = $1 AND tf.finding_id = $2 AND t.external_ref = $3
		)`, tenantID, findingID, ticketRef).Scan(&ok)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		// 2. Fallback check on action_ledger for backwards compatibility
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM action_ledger
			WHERE tenant_id = $1 AND finding_id = $2 AND action = $3
			AND status = 'done' AND result->>'ticket_id' = $4
		)`, tenantID, findingID, ticketAction, ticketRef).Scan(&ok)
	})
	return ok, err
}
