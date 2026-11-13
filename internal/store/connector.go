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

var (
	ErrConnectorNotFound = errors.New("store: connector not found")
)

// Connectors manages tenant-scoped external tool connectors (docs/04, docs/16 D69, docs/20 Milestone 3.1).
type Connectors interface {
	SaveConnector(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) error
	GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error)
	ListConnectors(ctx context.Context, tenantID uuid.UUID, connType ...domain.ConnectorType) ([]domain.Connector, error)
	DeleteConnector(ctx context.Context, tenantID uuid.UUID, name string) error
	UpdateConnectorStatus(ctx context.Context, tenantID uuid.UUID, name string, status domain.ConnectorStatus) error
}

func (s *PostgresStore) SaveConnector(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) error {
	if conn.ID == uuid.Nil {
		conn.ID = domain.NewID()
	}
	conn.TenantID = tenantID
	now := time.Now().UTC()
	if conn.CreatedAt.IsZero() {
		conn.CreatedAt = now
	}
	conn.UpdatedAt = now

	specJSON, err := json.Marshal(conn.Spec)
	if err != nil {
		return err
	}
	statusJSON, err := json.Marshal(conn.Status)
	if err != nil {
		return err
	}

	typeName := string(conn.Type)
	if typeName == "" {
		typeName = string(conn.Spec.Type)
	}

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO connector (id, tenant_id, name, type, spec, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
			ON CONFLICT (tenant_id, name)
			DO UPDATE SET
				type = EXCLUDED.type,
				spec = EXCLUDED.spec,
				status = EXCLUDED.status,
				updated_at = EXCLUDED.updated_at`,
			conn.ID, tenantID, conn.Name, typeName, specJSON, statusJSON, conn.CreatedAt, conn.UpdatedAt)
		return err
	})
}

func (s *PostgresStore) GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error) {
	var conn domain.Connector
	var specRaw, statusRaw []byte
	var typeStr string

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, type, spec, status, created_at, updated_at
			FROM connector
			WHERE tenant_id = $1 AND name = $2`, tenantID, name)

		err := row.Scan(&conn.ID, &conn.TenantID, &conn.Name, &typeStr, &specRaw, &statusRaw, &conn.CreatedAt, &conn.UpdatedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConnectorNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	conn.Type = domain.ConnectorType(typeStr)
	if len(specRaw) > 0 {
		if err := json.Unmarshal(specRaw, &conn.Spec); err != nil {
			return nil, err
		}
	}
	if len(statusRaw) > 0 {
		if err := json.Unmarshal(statusRaw, &conn.Status); err != nil {
			return nil, err
		}
	}

	return &conn, nil
}

func (s *PostgresStore) ListConnectors(ctx context.Context, tenantID uuid.UUID, connType ...domain.ConnectorType) ([]domain.Connector, error) {
	var list []domain.Connector

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error

		if len(connType) > 0 && connType[0] != "" {
			rows, err = tx.Query(ctx, `
				SELECT id, tenant_id, name, type, spec, status, created_at, updated_at
				FROM connector
				WHERE tenant_id = $1 AND type = $2
				ORDER BY name ASC`, tenantID, string(connType[0]))
		} else {
			rows, err = tx.Query(ctx, `
				SELECT id, tenant_id, name, type, spec, status, created_at, updated_at
				FROM connector
				WHERE tenant_id = $1
				ORDER BY name ASC`, tenantID)
		}
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var conn domain.Connector
			var specRaw, statusRaw []byte
			var typeStr string

			if err := rows.Scan(&conn.ID, &conn.TenantID, &conn.Name, &typeStr, &specRaw, &statusRaw, &conn.CreatedAt, &conn.UpdatedAt); err != nil {
				return err
			}

			conn.Type = domain.ConnectorType(typeStr)
			if len(specRaw) > 0 {
				_ = json.Unmarshal(specRaw, &conn.Spec)
			}
			if len(statusRaw) > 0 {
				_ = json.Unmarshal(statusRaw, &conn.Status)
			}
			list = append(list, conn)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}

func (s *PostgresStore) DeleteConnector(ctx context.Context, tenantID uuid.UUID, name string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM connector WHERE tenant_id = $1 AND name = $2`, tenantID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrConnectorNotFound
		}
		return nil
	})
}

func (s *PostgresStore) UpdateConnectorStatus(ctx context.Context, tenantID uuid.UUID, name string, status domain.ConnectorStatus) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE connector
			SET status = $1::jsonb, updated_at = $2
			WHERE tenant_id = $3 AND name = $4`,
			statusJSON, now, tenantID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrConnectorNotFound
		}
		return nil
	})
}
