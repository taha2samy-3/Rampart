package query

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/graph"
	"rampart/internal/ingest"
	"rampart/internal/query/grammar"
	"rampart/internal/risk"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// API provides HTTP handlers for the read path /api/v1 (docs/11, docs/16 D14, D16).
type API struct {
	store *ingest.MemoryStore
	feeds *enrich.FeedStore
}

// NewAPI creates an instance of API backed by an ingest store and threat intelligence feeds.
func NewAPI(store *ingest.MemoryStore, feeds *enrich.FeedStore) *API {
	return &API{
		store: store,
		feeds: feeds,
	}
}

// RegisterRoutes mounts all /api/v1 routes onto the router.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/findings", a.handleListFindings)
	mux.HandleFunc("GET /api/v1/findings/{id}", a.handleGetFinding)
	mux.HandleFunc("PATCH /api/v1/findings/{id}", a.handlePatchFinding)
	mux.HandleFunc("GET /api/v1/assets/{id}/sbom", a.handleGetAssetSBOM)
	mux.HandleFunc("GET /api/v1/applications/{id}/sbom", a.handleGetAssetSBOM) // alias per doc 11
	mux.HandleFunc("GET /api/v1/assets/{id}/sbom/graph", a.handleGetAssetSBOMGraph)
	mux.HandleFunc("GET /api/v1/applications/{id}/sbom/graph", a.handleGetAssetSBOMGraph)
	mux.HandleFunc("GET /api/v1/assets/{id}/sbom/path", a.handleGetAssetSBOMPath)
	mux.HandleFunc("GET /api/v1/applications/{id}/sbom/path", a.handleGetAssetSBOMPath)
	mux.HandleFunc("GET /api/v1/assets/{id}/vex", a.handleGetAssetVEX)
	mux.HandleFunc("GET /api/v1/applications/{id}/vex", a.handleGetAssetVEX) // alias per doc 11
}

// FindingResponse wraps a finding with its calculated risk and SLA details.
type FindingResponse struct {
	Finding     *domain.Finding      `json:"finding"`
	Risk        risk.ScoreBreakdown  `json:"risk"`
	SLADueDate  *time.Time           `json:"sla_due_date,omitempty"`
	Occurrences []*domain.Occurrence `json:"occurrences,omitempty"`
}

// ListFindingsResponse return payload.
type ListFindingsResponse struct {
	Items      []FindingResponse `json:"items"`
	Total      int               `json:"total"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)

	// 1. Fetch raw findings for tenant (isolated by RLS)
	all, err := a.store.ListFindings(r.Context(), tenantID)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to list findings"}`, http.StatusInternalServerError)
		return
	}

	// 2. Parse query string filter ?q=
	qParam := r.URL.Query().Get("q")
	var parsedQuery *grammar.Query
	if qParam != "" {
		pq, err := grammar.Parse(qParam)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid query syntax: %v"}`, err), http.StatusBadRequest)
			return
		}
		parsedQuery = &pq
	}

	// 3. Filter findings
	var filtered []*domain.Finding
	for _, f := range all {
		if parsedQuery != nil && !matchesQuery(f, *parsedQuery) {
			continue
		}
		filtered = append(filtered, f)
	}

	// 4. Sort findings
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "-score"
	}
	sortFindings(filtered, sortKey)

	// 5. Pagination
	limit := DefaultLimit
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsedL, err := strconv.Atoi(lStr); err == nil && parsedL > 0 {
			limit = parsedL
			if limit > MaxLimit {
				limit = MaxLimit
			}
		}
	}

	offset := 0
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		if decoded, err := base64.URLEncoding.DecodeString(cursor); err == nil {
			if parsedOffset, err := strconv.Atoi(string(decoded)); err == nil {
				offset = parsedOffset
			}
		}
	}

	total := len(filtered)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	page := filtered[start:end]

	var items []FindingResponse
	for _, f := range page {
		var vulnIDs []string
		if f.VulnerabilityID != nil {
			vulnIDs = []string{*f.VulnerabilityID}
		}

		rawF := domain.RawFinding{
			Severity: f.Severity,
			RuleID:   f.RuleID,
			Title:    f.Title,
		}

		riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
			Environment: "production",
			FirstSeen:   f.FirstSeen,
		}, a.feeds)

		slaDue := risk.CalculateSLADueDate(riskBreakdown.Band, "critical", f.FirstSeen, nil)

		items = append(items, FindingResponse{
			Finding:    f,
			Risk:       riskBreakdown,
			SLADueDate: &slaDue,
		})
	}

	nextCursor := ""
	if end < total {
		nextCursor = base64.URLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ListFindingsResponse{
		Items:      items,
		Total:      total,
		NextCursor: nextCursor,
	})
}

func (a *API) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	findingID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid finding UUID"}`, http.StatusBadRequest)
		return
	}

	finding, occs, err := a.store.GetFinding(r.Context(), tenantID, findingID)
	if err != nil || finding == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Finding not found"}`, http.StatusNotFound)
		return
	}

	var vulnIDs []string
	if finding.VulnerabilityID != nil {
		vulnIDs = []string{*finding.VulnerabilityID}
	}

	rawF := domain.RawFinding{
		Severity: finding.Severity,
		RuleID:   finding.RuleID,
		Title:    finding.Title,
	}

	riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
		Environment: "production",
		FirstSeen:   finding.FirstSeen,
	}, a.feeds)

	slaDue := risk.CalculateSLADueDate(riskBreakdown.Band, "critical", finding.FirstSeen, nil)

	res := FindingResponse{
		Finding:     finding,
		Risk:        riskBreakdown,
		SLADueDate:  &slaDue,
		Occurrences: occs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (a *API) handleGetAssetSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	assetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid asset UUID"}`, http.StatusBadRequest)
		return
	}

	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, assetID)
	if err != nil || sbom == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"SBOM not found for asset"}`, http.StatusNotFound)
		return
	}

	res := struct {
		SBOM       *domain.SBOM           `json:"sbom"`
		Components []domain.SBOMComponent `json:"components"`
	}{
		SBOM:       sbom,
		Components: comps,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (a *API) handleGetAssetSBOMGraph(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	assetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid asset UUID"}`, http.StatusBadRequest)
		return
	}

	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, assetID)
	if err != nil || sbom == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"SBOM not found for asset"}`, http.StatusNotFound)
		return
	}

	depGraph := graph.NewDependencyGraph(comps, sbom.Dependencies, sbom.RootComponent)
	depGraph.MarkDirectDependencies()

	directCount := 0
	transitiveCount := 0
	for _, c := range depGraph.Components {
		if c.Direct {
			directCount++
		} else {
			transitiveCount++
		}
	}

	res := struct {
		AssetID              uuid.UUID               `json:"asset_id"`
		Format               string                  `json:"format"`
		SpecVersion          string                  `json:"spec_version"`
		Root                 string                  `json:"root"`
		TotalComponents      int                     `json:"total_components"`
		DirectComponents     int                     `json:"direct_components"`
		TransitiveComponents int                     `json:"transitive_components"`
		Edges                []domain.DependencyEdge `json:"edges"`
		Mermaid              string                  `json:"mermaid"`
		Tree                 string                  `json:"tree"`
	}{
		AssetID:              assetID,
		Format:               sbom.Format,
		SpecVersion:          sbom.SpecVersion,
		Root:                 depGraph.RootRef,
		TotalComponents:      len(comps),
		DirectComponents:     directCount,
		TransitiveComponents: transitiveCount,
		Edges:                sbom.Dependencies,
		Mermaid:              depGraph.RenderMermaid(),
		Tree:                 depGraph.RenderTextTree(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (a *API) handleGetAssetSBOMPath(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	assetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid asset UUID"}`, http.StatusBadRequest)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"'target' query parameter is required"}`, http.StatusBadRequest)
		return
	}

	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, assetID)
	if err != nil || sbom == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"SBOM not found for asset"}`, http.StatusNotFound)
		return
	}

	depGraph := graph.NewDependencyGraph(comps, sbom.Dependencies, sbom.RootComponent)
	path := depGraph.FindShortestPath(target)
	if path == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"No path found to target in dependency graph"}`, http.StatusNotFound)
		return
	}

	depth := len(path) - 1
	if depth < 0 {
		depth = 0
	}

	res := struct {
		AssetID uuid.UUID `json:"asset_id"`
		Root    string    `json:"root"`
		Target  string    `json:"target"`
		Path    []string  `json:"path"`
		Depth   int       `json:"depth"`
	}{
		AssetID: assetID,
		Root:    depGraph.RootRef,
		Target:  target,
		Path:    path,
		Depth:   depth,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// PatchFindingRequest payload for PATCH /api/v1/findings/{id} (docs/11).
type PatchFindingRequest struct {
	State           string   `json:"state,omitempty"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impactStatement,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	SeverityReason  string   `json:"severityReason,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

func (a *API) handlePatchFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	findingID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid finding UUID"}`, http.StatusBadRequest)
		return
	}

	var req PatchFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	finding, occs, err := a.store.GetFinding(r.Context(), tenantID, findingID)
	if err != nil || finding == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Finding not found"}`, http.StatusNotFound)
		return
	}

	if req.State != "" {
		newState := domain.FindingState(req.State)
		if !newState.IsValid() {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid finding state"}`, http.StatusBadRequest)
			return
		}
		if err := finding.State.CanTransitionTo(newState); err != nil {
			http.Error(w, fmt.Sprintf(`{"type":"https://rampart.aspm.dev/problems/validation","title":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		finding.PreviousState = finding.State
		finding.State = newState
		finding.StateReason = req.Justification
		finding.Version++
		finding.UpdatedAt = time.Now().UTC()
	}

	if req.Severity != "" {
		newSev := domain.ParseSeverity(req.Severity)
		finding.Severity = newSev
		if req.SeverityReason != "" {
			finding.SeverityOverrideReason = &req.SeverityReason
		}
		finding.Version++
		finding.UpdatedAt = time.Now().UTC()
	}

	_ = a.store.UpsertFindings(r.Context(), tenantID, []*domain.Finding{finding})

	var vulnIDs []string
	if finding.VulnerabilityID != nil {
		vulnIDs = []string{*finding.VulnerabilityID}
	}

	rawF := domain.RawFinding{
		Severity: finding.Severity,
		RuleID:   finding.RuleID,
		Title:    finding.Title,
	}

	riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
		Environment: "production",
		FirstSeen:   finding.FirstSeen,
	}, a.feeds)

	slaDue := risk.CalculateSLADueDate(riskBreakdown.Band, "critical", finding.FirstSeen, nil)

	res := FindingResponse{
		Finding:     finding,
		Risk:        riskBreakdown,
		SLADueDate:  &slaDue,
		Occurrences: occs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (a *API) handleGetAssetVEX(w http.ResponseWriter, r *http.Request) {
	tenantID := resolveTenantID(r)
	idStr := r.PathValue("id")
	assetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid UUID"}`, http.StatusBadRequest)
		return
	}

	findings, err := a.store.ListFindings(r.Context(), tenantID)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to list findings"}`, http.StatusInternalServerError)
		return
	}

	type OpenVEXStatement struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products        []string `json:"products"`
		Status          string   `json:"status"`
		Justification   string   `json:"justification,omitempty"`
		ImpactStatement string   `json:"impact_statement,omitempty"`
	}

	var statements []OpenVEXStatement
	for _, f := range findings {
		if f.AssetID == assetID || f.ApplicationID == assetID {
			vulnName := f.RuleID
			if f.VulnerabilityID != nil && *f.VulnerabilityID != "" {
				vulnName = *f.VulnerabilityID
			}
			product := ""
			if f.Location.Package != nil {
				product = f.Location.Package.Purl
			}

			stmt := OpenVEXStatement{
				Status:          string(f.State),
				Justification:   f.StateReason,
				ImpactStatement: f.Title,
			}
			stmt.Vulnerability.Name = vulnName
			if product != "" {
				stmt.Products = []string{product}
			}
			statements = append(statements, stmt)
		}
	}

	res := struct {
		Context    string             `json:"@context"`
		ID         string             `json:"@id"`
		Author     string             `json:"author"`
		Timestamp  string             `json:"timestamp"`
		Version    int                `json:"version"`
		Statements []OpenVEXStatement `json:"statements"`
	}{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://rampart.aspm.dev/vex/%s", assetID),
		Author:     "Rampart ASPM",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    1,
		Statements: statements,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func matchesQuery(f *domain.Finding, q grammar.Query) bool {
	for _, term := range q.Terms {
		matched := false
		if term.Field != "" {
			matched = matchField(f, term.Field, term.Values)
		} else if term.Text != "" {
			matched = matchFreeText(f, term.Text)
		}

		if term.Negated {
			matched = !matched
		}

		if !matched {
			return false
		}
	}
	return true
}

func matchField(f *domain.Finding, field string, values []grammar.Value) bool {
	fieldVal := getFieldValue(f, field)

	for _, v := range values {
		if v.IsWildcard {
			if strings.HasPrefix(strings.ToLower(fieldVal), strings.ToLower(v.Prefix)) {
				return true
			}
		} else if v.IsRange {
			if num, err := strconv.Atoi(fieldVal); err == nil {
				if targetNum, err2 := strconv.Atoi(v.RangeVal); err2 == nil {
					switch v.RangeOp {
					case ">":
						if num > targetNum {
							return true
						}
					case ">=":
						if num >= targetNum {
							return true
						}
					case "<":
						if num < targetNum {
							return true
						}
					case "<=":
						if num <= targetNum {
							return true
						}
					}
				}
			}
		} else {
			if strings.EqualFold(fieldVal, v.Raw) {
				return true
			}
		}
	}

	return false
}

func getFieldValue(f *domain.Finding, field string) string {
	switch strings.ToLower(field) {
	case "state":
		return string(f.State)
	case "severity":
		return string(f.Severity)
	case "category":
		return string(f.Category)
	case "scanner":
		return f.RuleScannerFamily
	case "rule":
		return f.RuleID
	case "cve":
		if f.VulnerabilityID != nil {
			return *f.VulnerabilityID
		}
		return ""
	case "score":
		return strconv.Itoa(f.RiskScore)
	case "track":
		return f.Track
	case "path":
		return f.Location.PrimaryPath()
	case "purl":
		if f.Location.Package != nil {
			return f.Location.Package.PurlBase
		}
		return ""
	default:
		return ""
	}
}

func matchFreeText(f *domain.Finding, text string) bool {
	lower := strings.ToLower(text)
	if strings.Contains(strings.ToLower(f.Title), lower) {
		return true
	}
	if strings.Contains(strings.ToLower(f.Description), lower) {
		return true
	}
	if strings.Contains(strings.ToLower(f.RuleID), lower) {
		return true
	}
	if f.VulnerabilityID != nil && strings.Contains(strings.ToLower(*f.VulnerabilityID), lower) {
		return true
	}
	return false
}

func sortFindings(findings []*domain.Finding, sortKey string) {
	switch sortKey {
	case "-score":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].RiskScore > findings[j].RiskScore
		})
	case "score":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].RiskScore < findings[j].RiskScore
		})
	case "-seen":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].LastSeen.After(findings[j].LastSeen)
		})
	case "-age":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].FirstSeen.Before(findings[j].FirstSeen)
		})
	case "age":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].FirstSeen.After(findings[j].FirstSeen)
		})
	case "severity":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		})
	}
}

func resolveTenantID(r *http.Request) uuid.UUID {
	if tHeader := r.Header.Get("X-Tenant-ID"); tHeader != "" {
		if parsed, err := uuid.Parse(tHeader); err == nil {
			return parsed
		}
	}
	return uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
}
