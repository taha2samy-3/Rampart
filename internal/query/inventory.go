package query

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/store"
)

const (
	inventoryAssetLimit     = 1000
	inventoryComponentLimit = 500
	inventoryComponentMax   = 2000
)

// handleInventoryAssets is GET /api/v1/inventory: the scanned targets of the tenant with their open findings.
// The inventory page asked for it and got 404, so an uploaded and parsed SBOM never showed.
func (a *API) handleInventoryAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	rd, ok := a.store.(store.InventoryReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The inventory needs PostgreSQL")
		return
	}
	assets, err := rd.ListInventoryAssets(r.Context(), tenantID, inventoryAssetLimit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the inventory")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets})
}

// handleInventoryComponents is GET /api/v1/inventory/components?q=&limit=: the packages of the latest SBOM of every
// asset. total is the number that match q, which is more than components when the page is cut by limit.
func (a *API) handleInventoryComponents(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	rd, ok := a.store.(store.InventoryReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The inventory needs PostgreSQL")
		return
	}
	limit := inventoryComponentLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > inventoryComponentMax {
			problem(w, http.StatusBadRequest, "validation", "limit must be between 1 and "+strconv.Itoa(inventoryComponentMax))
			return
		}
		limit = n
	}
	q := r.URL.Query().Get("q")
	if len(q) > 200 {
		problem(w, http.StatusBadRequest, "validation", "q is longer than 200 characters")
		return
	}
	appFilter := strings.TrimSpace(r.URL.Query().Get("application"))
	if appFilter == "" {
		appFilter = strings.TrimSpace(r.URL.Query().Get("app"))
	}
	fetchLimit := limit
	if appFilter != "" && fetchLimit < inventoryComponentMax {
		fetchLimit = inventoryComponentMax
	}
	components, total, err := rd.ListInventoryComponents(r.Context(), tenantID, q, fetchLimit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the packages")
		return
	}
	if appFilter != "" {
		targetName := appFilter
		targetSlug := ""
		if appID, err := uuid.Parse(appFilter); err == nil {
			if app, err := a.store.GetApplication(r.Context(), tenantID, appID); err == nil && app != nil {
				targetName = app.Name
				targetSlug = app.Slug
			}
		}
		filtered := make([]store.InventoryComponent, 0, len(components))
		for _, c := range components {
			if strings.EqualFold(c.Application, targetName) || (targetSlug != "" && strings.EqualFold(c.Application, targetSlug)) {
				filtered = append(filtered, c)
			}
		}
		total = len(filtered)
		if len(filtered) > limit {
			filtered = filtered[:limit]
		}
		components = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components, "total": total, "truncated": total > len(components)})
}

// handleApplicationComponents answers GET /api/v1/applications/{id}/components.
// It returns the packages of the latest SBOM of the assets belonging to this application,
// indicating whether each package has open CVEs/vulnerabilities.
func (a *API) handleApplicationComponents(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
	rd, ok := a.store.(store.InventoryReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The inventory needs PostgreSQL")
		return
	}
	components, _, err := rd.ListInventoryComponents(r.Context(), tenantID, "", inventoryComponentMax)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read packages")
		return
	}
	out := make([]store.InventoryComponent, 0, len(components))
	for _, c := range components {
		if strings.EqualFold(c.Application, app.Name) || (app.Slug != "" && strings.EqualFold(c.Application, app.Slug)) {
			out = append(out, c)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"components": out,
		"total":      len(out),
	})
}

// ScanComponentRequest is the request body for POST /api/v1/inventory/components/scan.
type ScanComponentRequest struct {
	Purl      string `json:"purl"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	AssetID   string `json:"asset_id,omitempty"`
	ForceSync bool   `json:"force,omitempty"`
}

// ScanComponentResponse is the response returned when an on-demand scan is initiated.
type ScanComponentResponse struct {
	Status    string    `json:"status"`
	Purl      string    `json:"purl"`
	Message   string    `json:"message"`
	ScannedAt time.Time `json:"scanned_at"`
}

// handleScanComponent is POST /api/v1/inventory/components/scan. It is not built (docs/51 step 2.12): it used to
// ignore its purl and start a full re-score of the tenant in a goroutine per request, while the screens said a scan
// of that package had started. Scanning one package is not Rampart's work (matching packages to vulnerabilities is
// the analyzers', per SBOM: POST /assets/{id}/analyze or /applications/{id}/refresh-vulnerabilities), so it answers
// 501 with the reason instead of pretending. The role check stays first, so a viewer still learns nothing more.
func (a *API) handleScanComponent(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := a.requireAny(w, r, auth.RoleTriager); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://rampart.aspm.dev/problems/not-implemented",
		"title":  "Scanning one component is not built",
		"status": http.StatusNotImplemented,
		"detail": "Rampart does not scan a single package. Vulnerabilities are matched per SBOM by the analyzers: use \"Analyse again\" on the application (or POST /api/v1/assets/{id}/analyze).",
	})
}
