package query

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
	"rampart/internal/vex"
)

// handleExportVEX is GET /api/v1/applications/{id}/vex and /assets/{id}/vex (docs/05 section 7): the current
// decisions on the vulnerabilities of an application or an asset, as OpenVEX or CycloneDX.
func (a *API) handleExportVEX(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "No such application or asset")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "openvex"
	}
	if format != "openvex" && format != "cyclonedx" {
		msg := "format is openvex or cyclonedx"
		if format == "csaf" {
			msg = "CSAF export is not built; use openvex or cyclonedx"
		}
		problem(w, http.StatusBadRequest, "validation", msg)
		return
	}
	findings, err := a.store.ListFindings(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list findings")
		return
	}
	byApp := strings.Contains(r.URL.Path, "/applications/")
	var items []vex.Item
	for _, f := range findings {
		if (byApp && f.ApplicationID != id) || (!byApp && f.AssetID != id) {
			continue
		}
		if f.VulnerabilityID == nil || f.Location.Package == nil || f.Location.Package.Purl == "" {
			continue // only a vulnerability in a package is a VEX subject
		}
		items = append(items, vex.Item{
			Vuln: *f.VulnerabilityID, Purl: f.Location.Package.Purl, State: f.State, Justification: f.Justification,
			Impact: f.ImpactStatement, Action: f.StateReason, At: f.UpdatedAt,
		})
	}
	meta := vex.Meta{ID: fmt.Sprintf("https://rampart.aspm.dev/vex/%s/%s", tenantID, id), Author: "Rampart (" + actorOf(user) + ")", At: time.Now().UTC()}
	var doc map[string]any
	if format == "cyclonedx" {
		doc = vex.CycloneDX(meta, items)
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	} else {
		doc = vex.OpenVEX(meta, items)
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// VEXImportReport says what an import did, statement by statement.
type VEXImportReport = vex.Report

// VEXRejection names a statement and why it was not used.
type VEXRejection = vex.Rejection

// handleImportVEX is POST /api/v1/vex?application=&dryRun=: OpenVEX or CycloneDX VEX decides findings. A
// statement that matches nothing creates nothing; it is reported.
func (a *API) handleImportVEX(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	m, ok := a.store.(store.VEXMatcher)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "VEX import needs PostgreSQL")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, vex.MaxDocument+1))
	if err != nil || len(data) == 0 {
		problem(w, http.StatusBadRequest, "validation", "The body is empty")
		return
	}
	if len(data) > vex.MaxDocument {
		problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "The document is larger than 16 MiB")
		return
	}
	var appID *uuid.UUID
	if s := r.URL.Query().Get("application"); s != "" {
		id, perr := uuid.Parse(s)
		if perr != nil {
			problem(w, http.StatusBadRequest, "validation", "application is not an application id")
			return
		}
		appID = &id
	}
	doc, err := vex.Parse(data)
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	dry := r.URL.Query().Get("dryRun") == "true"
	author := strings.TrimSpace(doc.Author)
	if author == "" {
		author = "import"
	}
	actor := "vex:" + author

	var sc vex.Scorer
	if a.scorer != nil {
		sc = a.scorer
	}

	rep, err := vex.Apply(r.Context(), m, doc, tenantID, vex.ApplyOptions{
		DryRun:   dry,
		Actor:    actor,
		Author:   author,
		Importer: actorOf(user),
		AppID:    appID,
		Scorer:   sc,
		AllowApp: func(id uuid.UUID) bool { return scope.allows(id, auth.RoleTriager) },
	})
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to apply VEX document")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// statementCovers wraps vex.StatementCovers.
func statementCovers(st vex.Statement, f *domain.Finding) bool {
	return vex.StatementCovers(st, f)
}
