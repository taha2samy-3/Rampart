package query

import (
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

// FreshnessFeed represents the synchronization state of a threat intelligence feed.
type FreshnessFeed struct {
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	LastSync    *time.Time `json:"last_sync,omitempty"`
	Status      string     `json:"status"` // success | syncing | queued | idle | error | disabled
	Error       *string    `json:"error,omitempty"`
}

// FreshnessAnalyzer represents the newest analysis state of an analyzer for the application's SBOM.
type FreshnessAnalyzer struct {
	Name            string     `json:"name"`
	Kind            string     `json:"kind"` // external | sbom
	Scope           string     `json:"scope,omitempty"`
	State           string     `json:"state"` // completed | failed | pending | running | timed_out | cancelled | not_applicable | not_analysed
	LastAnalysedAt  *time.Time `json:"last_analysed_at,omitempty"`
	Findings        int        `json:"findings"`
	Created         int        `json:"created"`
	Closed          int        `json:"closed"`
	Error           string     `json:"error,omitempty"`
	InProgressSince *time.Time `json:"in_progress_since,omitempty"`
}

// FreshnessSBOM describes the newest SBOM held for the application.
type FreshnessSBOM struct {
	At         time.Time `json:"at"`
	Components int       `json:"components"`
}

// ApplicationFreshnessResponse is the payload for GET /api/v1/applications/{id}/freshness (docs/39 §5 Slice B).
type ApplicationFreshnessResponse struct {
	Feeds      []FreshnessFeed     `json:"feeds"`
	Analyzers  []FreshnessAnalyzer `json:"analyzers"`
	SBOM       *FreshnessSBOM      `json:"sbom,omitempty"`
	RescoredAt *time.Time          `json:"rescored_at,omitempty"`
}

// handleApplicationFreshness answers GET /api/v1/applications/{id}/freshness.
// It returns truthful synchronization and analysis timestamps without mutating any state.
func (a *API) handleApplicationFreshness(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}

	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}

	app, err := a.store.GetApplication(r.Context(), tenantID, appID)
	if err != nil || app == nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}

	resp := ApplicationFreshnessResponse{
		Feeds:     []FreshnessFeed{},
		Analyzers: []FreshnessAnalyzer{},
	}

	// 1. Threat intelligence feeds (global) and rescored_at calculation.
	var rescoredAt *time.Time
	if _, feedItems, err := a.getFeedItemsAndMirror(r.Context()); err == nil {
		for _, item := range feedItems {
			ff := FreshnessFeed{
				Name:        item.Name,
				DisplayName: item.DisplayName,
				LastSync:    item.LastSync,
				Status:      item.Status,
				Error:       item.Error,
			}
			if item.LastSync != nil && item.Status == "success" {
				if rescoredAt == nil || item.LastSync.After(*rescoredAt) {
					t := *item.LastSync
					rescoredAt = &t
				}
			}
			resp.Feeds = append(resp.Feeds, ff)
		}
	}
	resp.RescoredAt = rescoredAt

	// 2. Locate assets of the application and find the newest SBOM across all assets.
	var assetIDs []uuid.UUID
	if lister, ok := a.store.(appAssetLister); ok {
		if assets, err := lister.ListApplicationAssets(r.Context(), tenantID, appID); err == nil {
			for _, as := range assets {
				assetIDs = append(assetIDs, as.ID)
			}
		}
	}
	if len(assetIDs) == 0 {
		assetIDs = append(assetIDs, appID)
	}

	var (
		newestSBOM  *domain.SBOM
		newestComps int
	)
	for _, asID := range assetIDs {
		if sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, asID); err == nil && sbom != nil {
			if newestSBOM == nil || sbom.CreatedAt.After(newestSBOM.CreatedAt) {
				newestSBOM = sbom
				newestComps = sbom.ComponentCount
				if newestComps == 0 {
					newestComps = len(comps)
				}
			}
		}
	}

	if newestSBOM != nil {
		resp.SBOM = &FreshnessSBOM{
			At:         newestSBOM.CreatedAt,
			Components: newestComps,
		}

		seenAnalyzers := make(map[string]bool)
		if anStore, ok := a.store.(domain.AnalysisStore); ok {
			if analyses, err := anStore.ListSBOMAnalyses(r.Context(), tenantID, newestSBOM.ID); err == nil {
				for _, rec := range analyses {
					seenAnalyzers[rec.Analyzer.Name] = true
					fa := FreshnessAnalyzer{
						Name:     rec.Analyzer.Name,
						Kind:     rec.Analyzer.Kind,
						Scope:    rec.Analyzer.Scope,
						State:    string(rec.State),
						Findings: rec.Findings,
						Created:  rec.Created,
						Closed:   rec.Closed,
						Error:    rec.Error,
					}
					if rec.State.Settled() {
						if rec.FinishedAt != nil {
							fa.LastAnalysedAt = rec.FinishedAt
						} else if !rec.UpdatedAt.IsZero() {
							fa.LastAnalysedAt = &rec.UpdatedAt
						}
					} else {
						if rec.StartedAt != nil {
							fa.InProgressSince = rec.StartedAt
						} else if !rec.CreatedAt.IsZero() {
							fa.InProgressSince = &rec.CreatedAt
						}
					}
					resp.Analyzers = append(resp.Analyzers, fa)
				}
			}
		}

		// Also surface enabled analyzers that have not analysed this SBOM yet.
		if st, ok := a.store.(domain.AnalyzerStore); ok {
			if list, err := st.ListAnalyzers(r.Context(), tenantID); err == nil {
				for _, o := range list {
					if seenAnalyzers[o.Name] {
						continue
					}
					it := analyzerItemOf(o)
					if it.Enabled {
						resp.Analyzers = append(resp.Analyzers, FreshnessAnalyzer{
							Name:  o.Name,
							Kind:  analyzerKindName(o.Kind),
							Scope: o.Origin,
							State: "not_analysed",
						})
					}
				}
			}
		}

		sort.SliceStable(resp.Analyzers, func(i, j int) bool {
			return resp.Analyzers[i].Name < resp.Analyzers[j].Name
		})
	}

	writeJSON(w, http.StatusOK, resp)
}
