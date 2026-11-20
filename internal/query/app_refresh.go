package query

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// RefreshResponse is the answer of POST /api/v1/applications/{id}/refresh-vulnerabilities.
type RefreshResponse struct {
	Status         string `json:"status"` // "started", "idle", "in_progress", "cooldown"
	Queued         int    `json:"queued"`
	AlreadyRunning int    `json:"already_running,omitempty"`
	Analyzers      int    `json:"analyzers,omitempty"`
	Projects       int    `json:"projects,omitempty"`
	CooldownUntil  string `json:"cooldown_until,omitempty"`
	Message        string `json:"message"`
}

// handleRefreshVulnerabilities is POST /api/v1/applications/{id}/refresh-vulnerabilities.
// Re-evaluates vulnerabilities on the application's newest SBOMs across active analyzers (docs/39 Slices A-D).
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

	// 1. In-flight quota check (docs/39 Slice D.3): cap manual work across the platform.
	if c, ok := a.store.(interface {
		CountAnalysesInFlight(context.Context, time.Duration) (int, error)
	}); ok && a.maxInFlight > 0 {
		if inflight, err := c.CountAnalysesInFlight(r.Context(), time.Hour); err == nil && inflight >= a.maxInFlight {
			w.Header().Set("Retry-After", "30")
			problem(w, http.StatusTooManyRequests, "analysis-queue-full", fmt.Sprintf("Too many analyses are currently running or queued across the platform (%d in flight, limit %d). Try again in 30 seconds.", inflight, a.maxInFlight))
			return
		}
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

	cooldown := a.manualCooldown
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	hasSBOM := false
	var runningCount int
	var newestManualFinished *time.Time

	// 2. Inspect newest SBOMs of the application for in-flight analyses and manual cooldown (docs/39 Slice D.1, D.2).
	if st, ok := a.store.(domain.AnalysisStore); ok {
		for _, asID := range assetIDs {
			if s, _, err := a.store.GetSBOM(r.Context(), tenantID, asID); err == nil && s != nil {
				hasSBOM = true
				if analyses, err := st.ListSBOMAnalyses(r.Context(), tenantID, s.ID); err == nil {
					for _, an := range analyses {
						if an.State == domain.AnalysisPending || an.State == domain.AnalysisRunning {
							runningCount++
						}
						if an.Trigger == domain.TriggerManual && an.FinishedAt != nil {
							if newestManualFinished == nil || an.FinishedAt.After(*newestManualFinished) {
								t := *an.FinishedAt
								newestManualFinished = &t
							}
						}
					}
				}
			}
		}
	} else {
		for _, asID := range assetIDs {
			if s, _, err := a.store.GetSBOM(r.Context(), tenantID, asID); err == nil && s != nil {
				hasSBOM = true
			}
		}
	}

	if !hasSBOM {
		writeJSON(w, http.StatusAccepted, RefreshResponse{
			Status:    "idle",
			Queued:    0,
			Analyzers: activeAnalyzers,
			Projects:  len(assetIDs),
			Message:   "Nothing to check: no SBOM",
		})
		return
	}

	if runningCount > 0 {
		writeJSON(w, http.StatusAccepted, RefreshResponse{
			Status:         "in_progress",
			Queued:         0,
			AlreadyRunning: runningCount,
			Analyzers:      activeAnalyzers,
			Projects:       len(assetIDs),
			Message:        "Analysis is already running for this application",
		})
		return
	}

	if newestManualFinished != nil {
		elapsed := time.Since(*newestManualFinished)
		if elapsed < cooldown {
			remaining := cooldown - elapsed
			remSec := int(remaining.Seconds())
			remStr := fmt.Sprintf("%dm %ds", remSec/60, remSec%60)
			if remSec < 60 {
				remStr = fmt.Sprintf("%ds", remSec)
			}
			cooldownEnd := newestManualFinished.Add(cooldown)
			writeJSON(w, http.StatusAccepted, RefreshResponse{
				Status:        "cooldown",
				Queued:        0,
				Analyzers:     activeAnalyzers,
				Projects:      len(assetIDs),
				CooldownUntil: cooldownEnd.Format(time.RFC3339),
				Message:       fmt.Sprintf("Application was analysed recently; next manual check available in %s (cooldown %v)", remStr, cooldown),
			})
			return
		}
	}

	// 3. Dispatch to analyzers.
	totalQueued := 0
	for _, asID := range assetIDs {
		n, err := a.analysis.DispatchAsset(r.Context(), tenantID, asID, domain.TriggerManual)
		if err == nil {
			totalQueued += n
		}
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
