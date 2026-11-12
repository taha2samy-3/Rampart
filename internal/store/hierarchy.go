package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
	"rampart/internal/risk"
)

// EnsureHierarchyPath walks or creates nodes for segments (e.g. ["fintech", "payments"])
// ensuring each node exists with its path slug (e.g. "fintech", "fintech.payments") (D17, docs/04).
func (s *PostgresStore) EnsureHierarchyPath(ctx context.Context, tenantID uuid.UUID, segments []string) (*domain.HierarchyNode, error) {
	if len(segments) == 0 {
		return nil, nil
	}

	var lastNode *domain.HierarchyNode
	var pathParts []string

	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		for _, seg := range segments {
			slug := slugifyHierarchy(seg)
			if slug == "" {
				continue
			}
			pathParts = append(pathParts, slug)
			currentPath := strings.Join(pathParts, ".")

			var parentID *uuid.UUID
			if lastNode != nil {
				parentID = &lastNode.ID
			}

			// Try to find existing node by path
			var existing domain.HierarchyNode
			var pID *uuid.UUID
			var tags []string
			var meta []byte
			row := tx.QueryRow(ctx, `
				SELECT id, tenant_id, parent_id, name, slug, path, tags, metadata, created_at, updated_at
				FROM hierarchy_node WHERE tenant_id = $1 AND path = $2`, tenantID, currentPath)
			err := row.Scan(&existing.ID, &existing.TenantID, &pID, &existing.Name, &existing.Slug,
				&existing.Path, &tags, &meta, &existing.CreatedAt, &existing.UpdatedAt)

			if err == nil {
				existing.ParentID = pID
				existing.Tags = tags
				if len(meta) > 0 {
					_ = json.Unmarshal(meta, &existing.Metadata)
				}
				lastNode = &existing
				continue
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}

			// Create new node
			newNode := domain.HierarchyNode{
				ID:        domain.NewID(),
				TenantID:  tenantID,
				ParentID:  parentID,
				Name:      capitalize(seg),
				Slug:      slug,
				Path:      currentPath,
				Tags:      []string{},
				Metadata:  map[string]any{},
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}

			metaJSON, _ := json.Marshal(newNode.Metadata)
			_, err = tx.Exec(ctx, `
				INSERT INTO hierarchy_node (id, tenant_id, parent_id, name, slug, path, tags, metadata, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				ON CONFLICT (tenant_id, path) DO UPDATE SET updated_at = NOW()`,
				newNode.ID, tenantID, parentID, newNode.Name, newNode.Slug, newNode.Path,
				newNode.Tags, metaJSON, newNode.CreatedAt, newNode.UpdatedAt,
			)
			if err != nil {
				return fmt.Errorf("creating hierarchy node %q: %w", currentPath, err)
			}
			lastNode = &newNode
		}
		return nil
	})

	return lastNode, err
}

// ListHierarchyNodes returns all hierarchy nodes for a tenant ordered by path.
func (s *PostgresStore) ListHierarchyNodes(ctx context.Context, tenantID uuid.UUID) ([]*domain.HierarchyNode, error) {
	var nodes []*domain.HierarchyNode
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, parent_id, name, slug, path, tags, metadata, created_at, updated_at
			FROM hierarchy_node WHERE tenant_id = $1 ORDER BY path ASC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var n domain.HierarchyNode
			var pID *uuid.UUID
			var tags []string
			var meta []byte
			if err := rows.Scan(&n.ID, &n.TenantID, &pID, &n.Name, &n.Slug, &n.Path, &tags, &meta, &n.CreatedAt, &n.UpdatedAt); err != nil {
				return err
			}
			n.ParentID = pID
			n.Tags = tags
			if len(meta) > 0 {
				_ = json.Unmarshal(meta, &n.Metadata)
			}
			nodes = append(nodes, &n)
		}
		return rows.Err()
	})
	return nodes, err
}

// HierarchyRollups aggregates finding statistics and posture scores across hierarchy nodes (docs/06 section 2).
func (s *PostgresStore) HierarchyRollups(ctx context.Context, tenantID uuid.UUID) ([]domain.HierarchyRollup, error) {
	nodes, err := s.ListHierarchyNodes(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var rollups []domain.HierarchyRollup

	err = s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		for _, n := range nodes {
			r := domain.HierarchyRollup{
				HierarchyNode: *n,
				Open:          emptyBands(),
			}

			// 1. Children count
			_ = tx.QueryRow(ctx, `
				SELECT count(*) FROM hierarchy_node WHERE tenant_id = $1 AND parent_id = $2`, tenantID, n.ID).
				Scan(&r.ChildrenCount)

			// 2. Apps count and findings roll-up (matches this node path or any child path)
			pathPrefix := n.Path + ".%"
			var appCount int
			var crit, high, med, low, maxRisk, slaBreached int

			row := tx.QueryRow(ctx, `
				SELECT count(DISTINCT a.id),
				       count(f.id) FILTER (WHERE f.risk_band = 'critical'),
				       count(f.id) FILTER (WHERE f.risk_band = 'high'),
				       count(f.id) FILTER (WHERE f.risk_band = 'medium'),
				       count(f.id) FILTER (WHERE f.risk_band = 'low'),
				       coalesce(max(f.risk_score), 0),
				       count(f.id) FILTER (WHERE f.sla_breached_at IS NOT NULL)
				FROM application a
				LEFT JOIN finding f ON f.tenant_id = a.tenant_id AND f.application_id = a.id AND f.state IN `+activeStates+`
				WHERE a.tenant_id = $1 AND (a.hierarchy_node_id = $2 OR a.hierarchy_path = $3 OR a.hierarchy_path LIKE $4)`,
				tenantID, n.ID, n.Path, pathPrefix,
			)

			if err := row.Scan(&appCount, &crit, &high, &med, &low, &maxRisk, &slaBreached); err == nil {
				r.AppCount = appCount
				r.Open["critical"] = crit
				r.Open["high"] = high
				r.Open["medium"] = med
				r.Open["low"] = low
				r.RiskScore = maxRisk
				r.Exposure = crit + high
				r.SLABreached = slaBreached
				r.PostureScore = risk.CalculatePostureScore(r.Open, max(1, appCount), nil, 0)
			}

			rollups = append(rollups, r)
		}
		return nil
	})

	return rollups, err
}

func slugifyHierarchy(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			out = append(out, r)
		} else if r == '-' || r == ' ' || r == '.' {
			out = append(out, '_')
		}
	}
	return strings.Trim(string(out), "_")
}

func capitalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
