package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditRecord is one row of the audit log as the API returns it.
type AuditRecord struct {
	ID           uuid.UUID       `json:"id"`
	At           time.Time       `json:"at"`
	Actor        string          `json:"actor"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`
	IP           string          `json:"ip,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
}

// AuditFilter narrows a listing. Zero values mean "no filter".
type AuditFilter struct {
	Actor, Action, ResourceType string
	From, To                    time.Time
	// After continues a listing: rows strictly older than (At, ID), newest first.
	AfterAt time.Time
	AfterID uuid.UUID
}

// AuditReader lists the audit log of a tenant. Only the PostgreSQL store implements it.
type AuditReader interface {
	ListAudit(ctx context.Context, tenantID uuid.UUID, f AuditFilter, limit int) ([]AuditRecord, error)
}

// ListAudit returns up to limit rows, newest first. The caller asks for one more than it shows to know whether
// another page exists.
func (s *PostgresStore) ListAudit(ctx context.Context, tenantID uuid.UUID, f AuditFilter, limit int) ([]AuditRecord, error) {
	out := []AuditRecord{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var afterAt any
		if !f.AfterAt.IsZero() {
			afterAt = f.AfterAt
		}
		var from, to any
		if !f.From.IsZero() {
			from = f.From
		}
		if !f.To.IsZero() {
			to = f.To
		}
		rows, err := tx.Query(ctx, `
			SELECT id, at, actor->>'id', action, resource_type, resource_id, after, coalesce(host(ip), ''), coalesce(request_id, '')
			FROM audit_event
			WHERE tenant_id = $1
			  AND ($2 = '' OR actor->>'id' = $2)
			  AND ($3 = '' OR action = $3 OR action LIKE $3 || ' %')
			  AND ($4 = '' OR resource_type = $4)
			  AND ($5::timestamptz IS NULL OR at >= $5)
			  AND ($6::timestamptz IS NULL OR at < $6)
			  AND ($7::timestamptz IS NULL OR (at, id) < ($7, $8))
			ORDER BY at DESC, id DESC LIMIT $9`,
			tenantID, f.Actor, f.Action, f.ResourceType, from, to, afterAt, f.AfterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r AuditRecord
			var detail []byte
			if err := rows.Scan(&r.ID, &r.At, &r.Actor, &r.Action, &r.ResourceType, &r.ResourceID, &detail, &r.IP, &r.RequestID); err != nil {
				return err
			}
			r.Detail = detail
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
