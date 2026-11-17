package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AttestationTicketInfo is what a reader of an attestation sees of its renewal ticket.
type AttestationTicketInfo struct {
	Status string `json:"status"` // reserved (being opened) | opened | closed | failed (gave up)
	Ref    string `json:"ref,omitempty"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

// AttestationTicketRetrier lets an administrator send a ticket that gave up back to the outbox.
type AttestationTicketRetrier interface {
	// RetryFailedAttestationTicket reports whether a failed ticket of this tenant was put back (false: none to put back).
	RetryFailedAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID) (bool, error)
}

// AttestationTicketWork is a current "passed" attestation that ends within the warning window (14 days) and has no
// ticket yet, or whose ticket is waiting to be (re)tried (docs/16 D124).
type AttestationTicketWork struct {
	TenantID      uuid.UUID
	AttestationID uuid.UUID
	FrameworkID   string
	ControlID     string
	Application   string // the application's name; empty for an attestation of the whole tenant
	Owner         string // who renews it; the person who made it when none was named
	ExpiresAt     time.Time
	Attempts      int
}

// ClosableAttestationTicket is an open ticket whose attestation has been renewed.
type ClosableAttestationTicket struct {
	TenantID      uuid.UUID
	AttestationID uuid.UUID
	Connector     string
	Ref           string
}

// AttestationTicketOutbox is the renewal-ticket outbox: the sweeper reads across tenants, so it needs rampart_system.
// Only the PostgreSQL store implements it; the sweeper checks for it.
type AttestationTicketOutbox interface {
	// ListAttestationTicketWork returns the attestations that need a ticket opened, or retried.
	ListAttestationTicketWork(ctx context.Context, now time.Time, window time.Duration, limit int) ([]AttestationTicketWork, error)
	// ReserveAttestationTicket records, before the tracker is called, that this attestation is being ticketed. It says
	// whether the row is new: one that already existed means an earlier attempt may have created the issue.
	ReserveAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID) (created bool, err error)
	CompleteAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID, connector, ref, url string) error
	// RetryAttestationTicket schedules another attempt, or gives up (status failed) when giveUp is set.
	RetryAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID, errMsg string, next time.Time, giveUp bool) error
	// ListAttestationTicketsToClose returns open tickets whose attestation a newer, passed one has replaced.
	ListAttestationTicketsToClose(ctx context.Context, now time.Time, limit int) ([]ClosableAttestationTicket, error)
	MarkAttestationTicketClosed(ctx context.Context, tenantID, attestationID uuid.UUID) error
}

// coveredByTenant is the condition, for the attestation aliased x, that a whole-tenant attestation of the same control,
// the newest of them and passed, lasts beyond it. Such an attestation of one application is not the one that decides
// when the control stops reading as attested: the reading falls back to the tenant-wide one (attestationFor), so its
// ending is no news and needs no reminder or ticket.
func coveredByTenant(x string) string {
	return `(` + x + `.application_id IS NOT NULL AND EXISTS (SELECT 1 FROM compliance_attestation w
		WHERE w.tenant_id = ` + x + `.tenant_id AND w.framework_id = ` + x + `.framework_id AND w.control_id = ` + x + `.control_id
		  AND w.application_id IS NULL AND w.status = 'passed' AND w.expires_at > ` + x + `.expires_at
		  AND NOT EXISTS (SELECT 1 FROM compliance_attestation m
		                  WHERE m.tenant_id = w.tenant_id AND m.framework_id = w.framework_id AND m.control_id = w.control_id
		                    AND m.application_id IS NULL AND (m.attested_at, m.id) > (w.attested_at, w.id))))`
}

// newer is true when another attestation of the same control and application, in the same tenant, is newer than the row
// a. The newest one is the reading (the table is append-only and grows), so the queries below start from the
// attestations that end soon (idx_compliance_attestation_expiry) and keep those nothing newer has replaced, instead of
// ranking every attestation of every tenant on each pass.
const newer = `EXISTS (SELECT 1 FROM compliance_attestation m
		WHERE m.tenant_id = a.tenant_id AND m.framework_id = a.framework_id AND m.control_id = a.control_id
		  AND m.application_id IS NOT DISTINCT FROM a.application_id
		  AND (m.attested_at, m.id) > (a.attested_at, a.id))`

func (s *PostgresStore) ListAttestationTicketWork(ctx context.Context, now time.Time, window time.Duration, limit int) ([]AttestationTicketWork, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.tenant_id, a.id, a.framework_id, a.control_id, coalesce(ap.name, ''),
		       CASE WHEN a.owner <> '' THEN a.owner ELSE a.attested_by END, a.expires_at, coalesce(t.attempts, 0)
		FROM compliance_attestation a
		LEFT JOIN attestation_ticket t ON t.attestation_id = a.id
		LEFT JOIN application ap ON ap.id = a.application_id
		WHERE a.status = 'passed' AND a.expires_at > $1 AND a.expires_at <= $1::timestamptz + $2::interval
		  AND NOT `+newer+`
		  AND NOT `+coveredByTenant("a")+`
		  AND (t.attestation_id IS NULL OR (t.status = 'reserved' AND t.next_at <= $1))
		ORDER BY a.expires_at LIMIT $3`, now, window.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttestationTicketWork
	for rows.Next() {
		var w AttestationTicketWork
		if err := rows.Scan(&w.TenantID, &w.AttestationID, &w.FrameworkID, &w.ControlID, &w.Application, &w.Owner, &w.ExpiresAt, &w.Attempts); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ReserveAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO attestation_ticket (attestation_id, tenant_id) VALUES ($1, $2) ON CONFLICT (attestation_id) DO NOTHING`, attestationID, tenantID)
	return tag.RowsAffected() == 1, err
}

func (s *PostgresStore) CompleteAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID, connector, ref, url string) error {
	_, err := s.pool.Exec(ctx, `UPDATE attestation_ticket SET status = 'opened', connector = $3, ticket_ref = $4, ticket_url = $5,
		error = NULL, updated_at = NOW() WHERE tenant_id = $1 AND attestation_id = $2`, tenantID, attestationID, connector, ref, url)
	return err
}

func (s *PostgresStore) RetryAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID, errMsg string, next time.Time, giveUp bool) error {
	status := "reserved"
	if giveUp {
		status = "failed"
	}
	_, err := s.pool.Exec(ctx, `UPDATE attestation_ticket SET status = $3, attempts = attempts + 1, error = $4, next_at = $5, updated_at = NOW()
		WHERE tenant_id = $1 AND attestation_id = $2`, tenantID, attestationID, status, errMsg, next)
	return err
}

func (s *PostgresStore) ListAttestationTicketsToClose(ctx context.Context, now time.Time, limit int) ([]ClosableAttestationTicket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.tenant_id, t.attestation_id, t.connector, t.ticket_ref
		FROM attestation_ticket t
		JOIN compliance_attestation a ON a.id = t.attestation_id
		WHERE t.status = 'opened'
		  AND EXISTS (SELECT 1 FROM compliance_attestation n
		              WHERE n.tenant_id = a.tenant_id AND n.framework_id = a.framework_id AND n.control_id = a.control_id
		                AND n.application_id IS NOT DISTINCT FROM a.application_id AND n.id <> a.id
		                AND n.status = 'passed' AND n.expires_at > $1 AND (n.attested_at, n.id) > (a.attested_at, a.id)
		                AND NOT EXISTS (SELECT 1 FROM compliance_attestation m
		                                WHERE m.tenant_id = n.tenant_id AND m.framework_id = n.framework_id AND m.control_id = n.control_id
		                                  AND m.application_id IS NOT DISTINCT FROM n.application_id AND (m.attested_at, m.id) > (n.attested_at, n.id)))
		ORDER BY t.updated_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClosableAttestationTicket
	for rows.Next() {
		var c ClosableAttestationTicket
		if err := rows.Scan(&c.TenantID, &c.AttestationID, &c.Connector, &c.Ref); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkAttestationTicketClosed(ctx context.Context, tenantID, attestationID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE attestation_ticket SET status = 'closed', updated_at = NOW() WHERE tenant_id = $1 AND attestation_id = $2`, tenantID, attestationID)
	return err
}

func (s *PostgresStore) RetryFailedAttestationTicket(ctx context.Context, tenantID, attestationID uuid.UUID) (bool, error) {
	var n int64
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE attestation_ticket SET status = 'reserved', attempts = 0, error = NULL, next_at = NOW()
			WHERE tenant_id = $1 AND attestation_id = $2 AND status = 'failed'`, tenantID, attestationID)
		n = tag.RowsAffected()
		return err
	})
	return n == 1, err
}
