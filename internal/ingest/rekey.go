package ingest

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/store"
)

// RekeyStats says what a pass over a tenant did.
type RekeyStats struct {
	Renamed, Merged, Stale int
	// Unverified counts findings whose stored key could not be reproduced from what the finding keeps (an older
	// key format, or a changed rule). They are left as they are rather than guessed at.
	Unverified int
}

// RekeyStore is what the job needs.
type RekeyStore interface {
	store.Rekeyer
	CanonicalVulnIDs(ctx context.Context, tenantID uuid.UUID, ids []string) (map[string]string, error)
}

// RekeyTenant re-keys the software-composition findings of a tenant whose identifier has since become an alias of
// a CVE (docs/16 D11, D50). The key of such a finding is built from the identifier, so when enrichment links a GHSA
// id to its CVE the key a new scan computes is the CVE's. The job gives the finding that key; if a finding with it
// already exists the two are merged. The old key stays resolvable (finding_key_alias), so a tool that goes on
// reporting the GHSA id finds the same finding and a decision made on it is not lost.
func RekeyTenant(ctx context.Context, st RekeyStore, tenantID uuid.UUID) (RekeyStats, error) {
	var stats RekeyStats
	after := uuid.Nil
	for {
		page, err := st.ListRekeyCandidates(ctx, tenantID, after, 500)
		if err != nil || len(page) == 0 {
			return stats, err
		}
		after = page[len(page)-1].ID
		ids := make([]string, 0, len(page))
		for _, f := range page {
			ids = append(ids, *f.VulnerabilityID)
		}
		canon, err := st.CanonicalVulnIDs(ctx, tenantID, ids)
		if err != nil {
			return stats, err
		}
		for _, f := range page {
			if err := ctx.Err(); err != nil {
				return stats, err
			}
			to := canon[*f.VulnerabilityID]
			if to == "" || to == *f.VulnerabilityID {
				continue
			}
			oldKey, newKey := f.FindingKey, sca(f, to).FindingKey
			if sca(f, *f.VulnerabilityID).FindingKey != oldKey { // the inputs are not what built the stored key
				stats.Unverified++
				continue
			}
			if oldKey == newKey {
				continue
			}
			out, err := st.RekeyFinding(ctx, tenantID, f.ID, oldKey, newKey, to)
			if err != nil {
				return stats, err
			}
			switch out {
			case store.RekeyRenamed:
				stats.Renamed++
			case store.RekeyMerged:
				stats.Merged++
			default:
				stats.Stale++
			}
		}
	}
}

// sca recomputes the key of a software-composition finding as if its identifier were vuln.
func sca(f *domain.Finding, vuln string) normalize.FingerprintResult {
	return normalize.ComputeFingerprint(normalize.FingerprintParams{
		TenantID: f.TenantID, AssetID: f.AssetID, ApplicationID: f.ApplicationID, Track: f.Track,
		Scope: normalize.ScopeAsset, Family: f.RuleScannerFamily, Category: domain.CategorySCA, RuleID: f.RuleID,
		RawFinding: domain.RawFinding{Category: domain.CategorySCA, Location: f.Location, VulnIDs: []string{vuln}},
	})
}

// RekeyAll runs RekeyTenant for every tenant. It runs after a feed sync, before findings are re-scored: the
// sync is what brings the aliases.
func RekeyAll(ctx context.Context, st RekeyStore, tenants func(context.Context) ([]uuid.UUID, error), log *slog.Logger) {
	ids, err := tenants(ctx)
	if err != nil {
		log.Warn("rekey: listing tenants failed", "error", err)
		return
	}
	for _, t := range ids {
		stats, err := RekeyTenant(ctx, st, t)
		if err != nil {
			log.Warn("rekey failed", "tenant", t, "error", err)
			continue
		}
		if stats.Renamed+stats.Merged+stats.Unverified > 0 {
			log.Info("findings re-keyed after an alias change", "tenant", t, "renamed", stats.Renamed, "merged", stats.Merged, "unverified", stats.Unverified)
		}
	}
}
