package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InventoryAsset is a scanned target with the open findings it has, for the inventory page.
type InventoryAsset struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"` // repository, image, workload, url, package, host
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	Application   string     `json:"application_name,omitempty"`
	Critical      int        `json:"critical_findings"`
	High          int        `json:"high_findings"`
	Medium        int        `json:"medium_findings"`
	Low           int        `json:"low_findings"`
	Total         int        `json:"total_findings"`
	Components    int        `json:"component_count"`
	LastSeen      *time.Time `json:"last_seen_at,omitempty"`
}

// InventoryComponent is a package of the latest SBOM of an asset.
type InventoryComponent struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Purl            string    `json:"purl"`
	Type            string    `json:"type"` // the purl type: npm, maven, apk, golang...
	License         string    `json:"license,omitempty"`
	Direct          bool      `json:"direct"`
	AssetID         uuid.UUID `json:"asset_id"`
	Asset           string    `json:"asset_name"`
	Application     string    `json:"application_name,omitempty"`
	Vulnerabilities int       `json:"vulnerabilities"` // open findings of this package on this asset
}

// InventoryReader lists the assets and the SBOM packages of a tenant. Only the PostgreSQL store implements it.
type InventoryReader interface {
	ListInventoryAssets(ctx context.Context, tenantID uuid.UUID, limit int) ([]InventoryAsset, error)
	ListInventoryComponents(ctx context.Context, tenantID uuid.UUID, search string, limit int) (components []InventoryComponent, total int, err error)
}

// ListInventoryAssets returns the active assets, the ones with most open findings first.
func (s *PostgresStore) ListInventoryAssets(ctx context.Context, tenantID uuid.UUID, limit int) ([]InventoryAsset, error) {
	out := []InventoryAsset{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH fc AS (
				SELECT asset_id,
				       count(*) FILTER (WHERE severity = 'critical') AS crit,
				       count(*) FILTER (WHERE severity = 'high')     AS high,
				       count(*) FILTER (WHERE severity = 'medium')   AS med,
				       count(*) FILTER (WHERE severity IN ('low','info')) AS low,
				       count(*) AS total
				FROM finding
				WHERE tenant_id = $1 AND state IN `+activeStates+` AND detection = 'present'
				GROUP BY asset_id
			), latest AS (
				SELECT DISTINCT ON (asset_id) asset_id, component_count
				FROM sbom WHERE tenant_id = $1 ORDER BY asset_id, created_at DESC
			)
			SELECT a.id, COALESCE(NULLIF(a.display_name, ''), a.key), a.type, a.application_id, COALESCE(app.name, ''),
			       COALESCE(fc.crit, 0), COALESCE(fc.high, 0), COALESCE(fc.med, 0), COALESCE(fc.low, 0), COALESCE(fc.total, 0),
			       COALESCE(latest.component_count, 0), a.last_seen
			FROM asset a
			LEFT JOIN application app ON app.id = a.application_id AND app.tenant_id = a.tenant_id
			LEFT JOIN fc ON fc.asset_id = a.id
			LEFT JOIN latest ON latest.asset_id = a.id
			WHERE a.tenant_id = $1 AND a.active
			ORDER BY COALESCE(fc.crit, 0) DESC, COALESCE(fc.total, 0) DESC, 2
			LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a InventoryAsset
			if err := rows.Scan(&a.ID, &a.Name, &a.Kind, &a.ApplicationID, &a.Application, &a.Critical, &a.High, &a.Medium,
				&a.Low, &a.Total, &a.Components, &a.LastSeen); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ListInventoryComponents returns the packages of the latest SBOM of every asset, matching search in the name,
// the purl or the version, with the number of open findings each has. total is the number that match, which can
// be more than the rows returned (limit).
func (s *PostgresStore) ListInventoryComponents(ctx context.Context, tenantID uuid.UUID, search string, limit int) ([]InventoryComponent, int, error) {
	out := []InventoryComponent{}
	total := 0
	pattern := "%" + escapeLike(strings.TrimSpace(search)) + "%"
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		const base = `
			WITH latest AS (
				SELECT DISTINCT ON (asset_id) id, asset_id FROM sbom WHERE tenant_id = $1 ORDER BY asset_id, created_at DESC
			), comp AS (
				SELECT c.name, c.version, c.purl, c.purl_base, c.licenses, c.direct, l.asset_id
				FROM latest l JOIN sbom_component c ON c.sbom_id = l.id AND c.tenant_id = $1
				WHERE $2 = '%%' OR c.name ILIKE $2 OR c.purl ILIKE $2 OR c.version ILIKE $2
			)`
		if err := tx.QueryRow(ctx, base+` SELECT count(*) FROM comp`, tenantID, pattern).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, base+`,
			vc AS (
				SELECT o.asset_id, o.location->'package'->>'purl_base' AS pb, count(DISTINCT o.finding_id) AS n
				FROM occurrence o JOIN finding f ON f.id = o.finding_id AND f.tenant_id = o.tenant_id
				WHERE o.tenant_id = $1 AND o.location ? 'package' AND f.state IN `+activeStates+` AND f.detection = 'present'
				GROUP BY 1, 2
			)
			SELECT comp.name, comp.version, comp.purl, comp.licenses, comp.direct, comp.asset_id,
			       COALESCE(NULLIF(a.display_name, ''), a.key), COALESCE(app.name, ''), COALESCE(vc.n, 0)
			FROM comp
			JOIN asset a ON a.id = comp.asset_id AND a.tenant_id = $1
			LEFT JOIN application app ON app.id = a.application_id AND app.tenant_id = $1
			LEFT JOIN vc ON vc.asset_id = comp.asset_id AND vc.pb = comp.purl_base
			ORDER BY COALESCE(vc.n, 0) DESC, comp.name, comp.version
			LIMIT $3`, tenantID, pattern, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c InventoryComponent
			var licenses []string
			if err := rows.Scan(&c.Name, &c.Version, &c.Purl, &licenses, &c.Direct, &c.AssetID, &c.Asset, &c.Application, &c.Vulnerabilities); err != nil {
				return err
			}
			c.License = strings.Join(licenses, ", ")
			c.Type = purlType(c.Purl)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, total, err
}

// purlType is the type of a package url (pkg:npm/lodash@4 is npm); empty when it is not one.
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(t)
}

// escapeLike makes a user's text match literally in ILIKE: % and _ are wildcards, \ escapes them.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
