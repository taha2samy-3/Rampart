package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

// ErrTooManyProofs is returned when an acceptance already holds domain.MaxProofs files.
var ErrTooManyProofs = errors.New("store: this risk acceptance holds the most proof files allowed")

// AddProof records a proof file whose object is already stored (D60). The acceptance row is locked so two
// uploads at once cannot both pass the limit.
func (s *PostgresStore) AddProof(ctx context.Context, tenantID uuid.UUID, p *domain.RiskAcceptanceProof) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM risk_acceptance WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, p.RiskAcceptanceID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM risk_acceptance_proof WHERE tenant_id = $1 AND risk_acceptance_id = $2`, tenantID, p.RiskAcceptanceID).Scan(&n); err != nil {
			return err
		}
		if n >= domain.MaxProofs {
			return ErrTooManyProofs
		}
		return tx.QueryRow(ctx, `
			INSERT INTO risk_acceptance_proof (id, tenant_id, risk_acceptance_id, name, content_type, size_bytes, sha256, object_ref, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING uploaded_at`,
			p.ID, tenantID, p.RiskAcceptanceID, p.Name, p.ContentType, p.SizeBytes, p.SHA256, p.ObjectRef, p.UploadedBy).Scan(&p.UploadedAt)
	})
}

const proofCols = `id, risk_acceptance_id, name, content_type, size_bytes, sha256, object_ref, uploaded_by, uploaded_at`

func scanProof(row pgx.Row) (*domain.RiskAcceptanceProof, error) {
	var p domain.RiskAcceptanceProof
	err := row.Scan(&p.ID, &p.RiskAcceptanceID, &p.Name, &p.ContentType, &p.SizeBytes, &p.SHA256, &p.ObjectRef, &p.UploadedBy, &p.UploadedAt)
	return &p, err
}

// ListProofs returns the proof files of an acceptance, oldest first.
func (s *PostgresStore) ListProofs(ctx context.Context, tenantID, acceptanceID uuid.UUID) ([]*domain.RiskAcceptanceProof, error) {
	out := []*domain.RiskAcceptanceProof{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+proofCols+` FROM risk_acceptance_proof
			WHERE tenant_id = $1 AND risk_acceptance_id = $2 ORDER BY uploaded_at, id`, tenantID, acceptanceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProof(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// GetProof returns one proof file of an acceptance.
func (s *PostgresStore) GetProof(ctx context.Context, tenantID, acceptanceID, proofID uuid.UUID) (*domain.RiskAcceptanceProof, error) {
	var p *domain.RiskAcceptanceProof
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		p, err = scanProof(tx.QueryRow(ctx, `SELECT `+proofCols+` FROM risk_acceptance_proof
			WHERE tenant_id = $1 AND risk_acceptance_id = $2 AND id = $3`, tenantID, acceptanceID, proofID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}
