package query

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/query/grammar"
	"rampart/internal/telemetry"

	"github.com/google/uuid"
)

// VulnerabilitySource reads the record the feeds hold of a vulnerability. PostgreSQL implements it on the
// feed syncer; the in-memory store has no feeds.
type VulnerabilitySource interface {
	Record(ctx context.Context, id string) (*enrich.VulnerabilityRecord, error)
}

// VulnerabilityRefresher fetches a vulnerability's record live from the upstream advisory sources: the "Refresh"
// button, and nothing else (a page view reads the database only). enrich.LiveAdvisory implements it with single
// flight per id and a cooldown; it returns *enrich.RefreshCooldownError or enrich.ErrLiveFetchOff when it will not fetch.
type VulnerabilityRefresher interface {
	Refresh(ctx context.Context, id string) (*enrich.VulnerabilityRecord, error)
}

// vulnIDPattern is what an identifier may hold (CVE-2021-44228, GHSA-xxxx-xxxx-xxxx, PYSEC-2020-1, OSV ids).
// It is checked before the id goes into a filter, so the path cannot carry a query of its own.
var vulnIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// VulnerabilityResponse is GET /api/v1/vulnerabilities/{id} (docs/11).
type VulnerabilityResponse struct {
	ID     string                      `json:"id"`
	Known  bool                        `json:"known"` // a feed has the record; false still gives the public links
	Record *enrich.VulnerabilityRecord `json:"record,omitempty"`
	Links  []string                    `json:"links"`
}

// handleGetVulnerability returns what the feeds know of an id, whatever parser reported it: the description,
// CVSS, EPSS, KEV, CWE, references and aliases. A finding whose report carried only the id is described by this.
func (a *API) handleGetVulnerability(w http.ResponseWriter, r *http.Request) {
	if _, err := a.resolveTenant(r); err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !vulnIDPattern.MatchString(id) {
		problem(w, http.StatusBadRequest, "validation", "Not a vulnerability identifier")
		return
	}
	out := VulnerabilityResponse{ID: strings.ToUpper(id), Links: enrich.VulnerabilityLinks(strings.ToUpper(id), false)}
	if src, ok := a.intel.(VulnerabilitySource); ok {
		rec, err := src.Record(r.Context(), id)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to read the vulnerability record")
			return
		}
		if rec != nil {
			out.Known, out.Record, out.ID, out.Links = true, rec, rec.ID, rec.Links
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRefreshVulnerability fetches a vulnerability live from the upstream advisory sources (OSV, then NVD) and
// stores it (docs/44, docs/51 step 1.5). It needs the triager role: the fetch spends the server's upstream quota,
// which a viewer must not be able to drain. One fetch per id runs at a time and the same id is not fetched again
// within the cooldown (AGENTS.md section 4): a later click gets 429 with Retry-After. The upstream error is logged
// with the request id and not echoed: it can carry upstream URLs and answers that are not the caller's to read.
func (a *API) handleRefreshVulnerability(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireRole(w, r, auth.RoleTriager); !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !vulnIDPattern.MatchString(id) {
		problem(w, http.StatusBadRequest, "validation", "Not a vulnerability identifier")
		return
	}
	ref, ok := a.intel.(VulnerabilityRefresher)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "This server cannot fetch advisories live: it needs PostgreSQL")
		return
	}
	out := VulnerabilityResponse{ID: strings.ToUpper(id), Links: enrich.VulnerabilityLinks(strings.ToUpper(id), false)}
	rec, err := ref.Refresh(r.Context(), id)
	var cool *enrich.RefreshCooldownError
	switch {
	case errors.As(err, &cool):
		secs := int(math.Ceil(cool.RetryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		problem(w, http.StatusTooManyRequests, "refresh-cooldown", fmt.Sprintf("This vulnerability was refreshed less than %d minutes ago. Try again in %d seconds.", int(enrich.DefaultRefreshCooldown/time.Minute), secs))
		return
	case errors.Is(err, enrich.ErrLiveFetchOff):
		problem(w, http.StatusConflict, "live-fetch-off", "This server does not fetch advisories live (advisory mode stored): the record is what the feeds hold")
		return
	case err != nil:
		reqID := telemetry.RequestID(r.Context())
		slog.Warn("vulnerability refresh: the upstream advisory sources failed", "id", id, "request_id", reqID, "error", err)
		problem(w, http.StatusBadGateway, "upstream_sync_failed", "The upstream advisory sources (OSV, NVD) could not be read; the reason is in the server log under request id "+reqID)
		return
	}
	if rec != nil {
		out.Known, out.Record, out.ID, out.Links = true, rec, rec.ID, rec.Links
	}
	writeJSON(w, http.StatusOK, out)
}

// ImpactApplication is one application a vulnerability is found in.
type ImpactApplication struct {
	ID          uuid.UUID       `json:"id"`
	Slug        string          `json:"slug"`
	Name        string          `json:"name"`
	Findings    int             `json:"findings"`
	Open        int             `json:"open"`
	MaxSeverity domain.Severity `json:"max_severity"`
	MaxScore    int             `json:"max_risk_score"`
	AssetIDs    []uuid.UUID     `json:"asset_ids"`
}

// VulnerabilityImpact is GET /api/v1/vulnerabilities/{id}/impact (docs/11): where this tenant has the vulnerability.
type VulnerabilityImpact struct {
	ID           string              `json:"id"`
	Findings     int                 `json:"findings"`
	Open         int                 `json:"open"`
	Applications []ImpactApplication `json:"applications"`
	Truncated    bool                `json:"truncated,omitempty"`
}

const impactLimit = 5000

// handleVulnerabilityImpact lists the applications and assets of this tenant that have the vulnerability, by the
// id or any alias of it (a GHSA finding counts for its CVE), most affected first.
func (a *API) handleVulnerabilityImpact(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !vulnIDPattern.MatchString(id) {
		problem(w, http.StatusBadRequest, "validation", "Not a vulnerability identifier")
		return
	}
	querier, ok := a.store.(FindingQuerier)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Store does not support finding queries")
		return
	}
	q, err := grammar.Parse("cve:" + id)
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Not a vulnerability identifier")
		return
	}
	found, err := querier.QueryFindings(r.Context(), tenantID, &q, "-score", impactLimit+1, nil)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the findings")
		return
	}
	out := VulnerabilityImpact{ID: strings.ToUpper(id), Applications: []ImpactApplication{}}
	if len(found) > impactLimit {
		found, out.Truncated = found[:impactLimit], true
	}
	byApp := map[uuid.UUID]*ImpactApplication{}
	assets := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, f := range found {
		out.Findings++
		active := f.State.IsActive()
		if active {
			out.Open++
		}
		appID := f.ApplicationID
		ia := byApp[appID]
		if ia == nil {
			ia = &ImpactApplication{ID: appID, AssetIDs: []uuid.UUID{}}
			if app, err := a.store.GetApplication(r.Context(), tenantID, appID); err == nil && app != nil {
				ia.Slug, ia.Name = app.Slug, app.Name
			}
			byApp[appID], assets[appID] = ia, map[uuid.UUID]bool{}
		}
		ia.Findings++
		if active {
			ia.Open++
			if f.Severity.Rank() > ia.MaxSeverity.Rank() {
				ia.MaxSeverity = f.Severity
			}
			ia.MaxScore = max(ia.MaxScore, f.RiskScore)
		}
		if !assets[appID][f.AssetID] {
			assets[appID][f.AssetID] = true
			ia.AssetIDs = append(ia.AssetIDs, f.AssetID)
		}
	}
	for _, ia := range byApp {
		out.Applications = append(out.Applications, *ia)
	}
	sort.Slice(out.Applications, func(i, j int) bool {
		x, y := out.Applications[i], out.Applications[j]
		if x.Open != y.Open {
			return x.Open > y.Open
		}
		return x.Name < y.Name
	})
	writeJSON(w, http.StatusOK, out)
}
