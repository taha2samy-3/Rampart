package query

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// RefreshResponse is the answer of POST /api/v1/applications/{id}/refresh-vulnerabilities.
type RefreshResponse struct {
	Status         string `json:"status"` // "started", "idle", "in_progress"
	Queued         int    `json:"queued"`
	AlreadyRunning int    `json:"already_running,omitempty"`
	Analyzers      int    `json:"analyzers,omitempty"`
	Projects       int    `json:"projects,omitempty"`
	Message        string `json:"message"`
}

// handleRefreshVulnerabilities is POST /api/v1/applications/{id}/refresh-vulnerabilities.
// Re-evaluates vulnerabilities on the application's newest SBOMs across active analyzers.
func (a *API) handleRefreshVulnerabilities(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Not an application id")
		return
	}
	if app, err := a.store.GetApplication(r.Context(), tenantID, appID); err != nil || app == nil {
		problem(w, http.StatusNotFound, "not-found", "No such application")
		return
	}
	if !scope.allows(appID, auth.RoleTriager) {
		problem(w, http.StatusForbidden, "forbidden", "Refreshing needs the triager role on this application")
		return
	}

	activeAnalyzers := 0
	if st, ok := a.store.(domain.AnalyzerStore); ok {
		if list, err := st.ListAnalyzers(r.Context(), tenantID); err == nil {
			for _, o := range list {
				if o.Error == "" {
					activeAnalyzers++
				}
			}
		}
	}

	if a.analysis == nil {
		writeJSON(w, http.StatusAccepted, RefreshResponse{
			Status:    "idle",
			Queued:    0,
			Analyzers: activeAnalyzers,
			Projects:  1,
			Message:   "Analysis is switched off on this server (analysis.enabled)",
		})
		return
	}

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

	totalQueued := 0
	hasSBOM := false
	for _, asID := range assetIDs {
		if a.store != nil {
			if s, _, err := a.store.GetSBOM(r.Context(), tenantID, asID); err == nil && s != nil {
				hasSBOM = true
			}
		}
		n, err := a.analysis.DispatchAsset(r.Context(), tenantID, asID, domain.TriggerManual)
		if err == nil {
			totalQueued += n
		}
	}

	if !hasSBOM && totalQueued == 0 {
		writeJSON(w, http.StatusAccepted, RefreshResponse{
			Status:    "idle",
			Queued:    0,
			Analyzers: activeAnalyzers,
			Projects:  len(assetIDs),
			Message:   "Nothing to check: no SBOM",
		})
		return
	}

	if totalQueued > 0 {
		word := "analyses"
		if totalQueued == 1 {
			word = "analysis"
		}
		writeJSON(w, http.StatusAccepted, RefreshResponse{
			Status:    "started",
			Queued:    totalQueued,
			Analyzers: activeAnalyzers,
			Projects:  len(assetIDs),
			Message:   fmt.Sprintf("Queued %d %s for application", totalQueued, word),
		})
		return
	}

	writeJSON(w, http.StatusAccepted, RefreshResponse{
		Status:         "in_progress",
		Queued:         0,
		AlreadyRunning: activeAnalyzers,
		Analyzers:      activeAnalyzers,
		Projects:       len(assetIDs),
		Message:        "Analysis is already running or up to date",
	})
}
