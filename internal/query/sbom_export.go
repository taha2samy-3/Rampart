package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/sbomexport"
	"rampart/internal/store"
)

type appAssetLister interface {
	ListApplicationAssets(ctx context.Context, tenantID, appID uuid.UUID) ([]store.AppAsset, error)
}

// sbomFormat reads ?format=: cyclonedx (default) or spdx.
func sbomFormat(w http.ResponseWriter, r *http.Request) (string, bool) {
	f := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch f {
	case "", "cyclonedx":
		return "cyclonedx", true
	case "spdx":
		return "spdx", true
	}
	problem(w, http.StatusBadRequest, "validation", "format must be cyclonedx or spdx")
	return "", false
}

func (a *API) writeSBOM(w http.ResponseWriter, format, filename string, subject sbomexport.Subject, parts []sbomexport.Part) {
	now := time.Now()
	var doc map[string]any
	ext := "cdx.json"
	ct := "application/vnd.cyclonedx+json; version=1.6"
	if format == "spdx" {
		// The namespace only has to be unique (SPDX 2.3 §6.5); it is not fetched.
		doc, ext, ct = sbomexport.SPDX(subject, parts, now, "https://spdx.rampart.aspm.dev"), "spdx.json", "application/spdx+json"
	} else {
		doc = sbomexport.CycloneDX(subject, parts, now)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, filename, ext))
	_ = json.NewEncoder(w).Encode(doc)
}

// exportAssetSBOM answers GET /api/v1/assets/{id}/sbom?format=cyclonedx|spdx: the asset's latest SBOM as a standard
// document (D95). Without format the endpoint keeps its JSON view.
func (a *API) exportAssetSBOM(w http.ResponseWriter, r *http.Request, tenantID, assetID uuid.UUID) {
	format, ok := sbomFormat(w, r)
	if !ok {
		return
	}
	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, assetID)
	if err != nil || sbom == nil {
		problem(w, http.StatusNotFound, "not-found", "No SBOM for this asset")
		return
	}
	name := "asset " + assetID.String()
	a.writeSBOM(w, format, "asset-"+assetID.String()[:8], sbomexport.Subject{Name: name}, []sbomexport.Part{{AssetName: name, SBOM: sbom, Components: comps}})
}

// handleApplicationSBOM answers GET /api/v1/applications/{id}/sbom?format=cyclonedx|spdx (doc 11): one document
// merging the latest SBOM of every asset of the application. A component found in several assets appears once and
// names each asset it came from. Before D95 this route read the application id as an asset id and found nothing.
func (a *API) handleApplicationSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	format, ok := sbomFormat(w, r)
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
	lister, ok := a.store.(appAssetLister)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The merged SBOM needs PostgreSQL")
		return
	}
	assets, err := lister.ListApplicationAssets(r.Context(), tenantID, appID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Listing the application's assets failed")
		return
	}
	var parts []sbomexport.Part
	for _, as := range assets {
		if sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, as.ID); err == nil && sbom != nil {
			parts = append(parts, sbomexport.Part{AssetName: as.Name, SBOM: sbom, Components: comps})
		}
	}
	if len(parts) == 0 {
		problem(w, http.StatusNotFound, "not-found", "No asset of this application has an SBOM yet: upload one (rampart sbom upload)")
		return
	}
	name := app.Slug
	if name == "" {
		name = app.Name
	}
	a.writeSBOM(w, format, name+"-sbom", sbomexport.Subject{Name: app.Name}, parts)
}
