package query

import (
	"context"
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
	components, total, err := rd.ListInventoryComponents(r.Context(), tenantID, q, limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the packages")
		return
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

// handleScanComponent is POST /api/v1/inventory/components/scan. It does NOT scan the package: matching packages to
// vulnerabilities is Dependency-Track's work, per project (POST /applications/{id}/refresh-vulnerabilities asks for
// that). What it does is recalculate the risk scores of the tenant's findings against the feeds as they are now, which
// is why it needs triage rights and says so in its answer (D126).
func (a *API) handleScanComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, _, _, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	var req ScanComponentRequest
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Purl == "" {
		req.Purl = r.URL.Query().Get("purl")
	}
	if req.Purl == "" {
		problem(w, http.StatusBadRequest, "validation", "purl is required")
		return
	}
	if a.scorer != nil {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			_, _ = a.scorer.Rescore(bgCtx, tenantID)
		}()
	}
	writeJSON(w, http.StatusAccepted, ScanComponentResponse{
		Status:    "started",
		Purl:      req.Purl,
		Message:   "Risk scores are being recalculated against the current feeds. This does not scan " + req.Purl + "; use Refresh from Dependency-Track on the application to pull new vulnerabilities.",
		ScannedAt: time.Now().UTC(),
	})
}
