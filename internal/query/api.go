package query

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/graph"
	"rampart/internal/query/grammar"
	"rampart/internal/risk"
	"rampart/internal/store"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// API provides HTTP handlers for the read path /api/v1 (docs/11, docs/16 D14, D16).
type API struct {
	store   store.Store
	feeds   *enrich.FeedStore
	authn   *auth.Authenticator
	hmacKey []byte
}

// NewAPI creates an instance of API backed by an ingest store and threat intelligence feeds.
func NewAPI(s store.Store, feeds *enrich.FeedStore) *API {
	return NewAPIWithAuth(s, feeds, nil)
}

// NewAPIWithAuth creates an instance of API with an explicit authenticator.
func NewAPIWithAuth(s store.Store, feeds *enrich.FeedStore, authn *auth.Authenticator) *API {
	if authn == nil {
		authn = auth.NewAuthenticatorWithStore(s)
	}
	return &API{
		store:   s,
		feeds:   feeds,
		authn:   authn,
		hmacKey: []byte("rampart-cursor-hmac-secret-v1"),
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

type cursorData struct {
	Offset int    `json:"offset"`
	Sort   string `json:"sort"`
	Filter string `json:"filter"`
}

func (a *API) encodeCursor(offset int, sortKey, filter string) string {
	data, _ := json.Marshal(cursorData{Offset: offset, Sort: sortKey, Filter: filter})
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))
	combined := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(data), sig)
	return base64.RawURLEncoding.EncodeToString([]byte(combined))
}

func (a *API) decodeCursor(cursor string, sortKey, filter string) (int, error) {
	rawCombined, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(string(rawCombined), ".")
	if len(parts) != 2 {
		return 0, errors.New("invalid cursor format")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, err
	}
	expectedMAC := hmac.New(sha256.New, a.hmacKey)
	expectedMAC.Write(data)
	if hex.EncodeToString(expectedMAC.Sum(nil)) != parts[1] {
		return 0, errors.New("invalid cursor signature")
	}
	var cd cursorData
	if err := json.Unmarshal(data, &cd); err != nil {
		return 0, err
	}
	if cd.Sort != sortKey || cd.Filter != filter {
		return 0, errors.New("cursor invalidated by sort or filter change")
	}
	return cd.Offset, nil
}

func (a *API) resolveTenant(r *http.Request) (uuid.UUID, error) {
	if tid, err := auth.TenantFromContext(r.Context()); err == nil && tid != domain.NilID {
		return tid, nil
	}
	if a.authn != nil {
		if u, err := a.authn.AuthenticateRequest(r); err == nil && u != nil && u.TenantID != domain.NilID {
			return u.TenantID, nil
		}
	}
	return domain.NilID, auth.ErrUnauthorized
}

func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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

	// 5. Pagination with HMAC signed cursor (D16)
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
		if parsedOffset, err := a.decodeCursor(cursor, sortKey, qParam); err == nil {
			offset = parsedOffset
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

		env := f.Track
		if env == "" {
			env = "production"
		}
		riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
			Environment: env,
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
		nextCursor = a.encodeCursor(end, sortKey, qParam)
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
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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

	env := finding.Track
	if env == "" {
		env = "production"
	}
	riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
		Environment: env,
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
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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
		Edges:                depGraph.Edges,
		Mermaid:              depGraph.RenderMermaid(),
		Tree:                 depGraph.RenderTextTree(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (a *API) handleGetAssetSBOMPath(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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
	if len(path) == 0 {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"No dependency path to target found"}`, http.StatusNotFound)
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
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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

	var events []*domain.FindingEvent

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
		oldState := finding.State
		finding.PreviousState = oldState
		finding.State = newState
		finding.StateReason = req.Justification
		finding.Version++
		finding.UpdatedAt = time.Now().UTC()

		fromStateJSON, _ := json.Marshal(oldState)
		toStateJSON, _ := json.Marshal(newState)
		events = append(events, &domain.FindingEvent{
			ID:        domain.NewID(),
			FindingID: finding.ID,
			At:        time.Now().UTC(),
			Actor:     "user",
			Type:      "state_changed",
			From:      fromStateJSON,
			To:        toStateJSON,
			Note:      req.Justification,
		})
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
	if len(events) > 0 {
		_ = a.store.RecordFindingEvents(r.Context(), tenantID, events)
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

	env := finding.Track
	if env == "" {
		env = "production"
	}
	riskBreakdown := risk.EvaluateRisk(rawF, vulnIDs, risk.Context{
		Environment: env,
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
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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
			ID string `json:"@id"`
		} `json:"vulnerability"`
		Status        string `json:"status"`
		Justification string `json:"justification,omitempty"`
		Impact        string `json:"impact_statement,omitempty"`
	}

	var statements []OpenVEXStatement
	for _, f := range findings {
		if f.AssetID == assetID && f.VulnerabilityID != nil {
			status := string(f.State)
			stmt := OpenVEXStatement{
				Status:        status,
				Justification: f.StateReason,
			}
			stmt.Vulnerability.ID = *f.VulnerabilityID
			statements = append(statements, stmt)
		}
	}

	doc := struct {
		Context    string             `json:"@context"`
		ID         string             `json:"@id"`
		Author     string             `json:"author"`
		Role       string             `json:"role"`
		Timestamp  time.Time          `json:"timestamp"`
		Statements []OpenVEXStatement `json:"statements"`
	}{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://rampart.aspm.dev/vex/%s", assetID),
		Author:     "Rampart ASPM",
		Role:       "Security Platform",
		Timestamp:  time.Now().UTC(),
		Statements: statements,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

func matchesQuery(f *domain.Finding, q grammar.Query) bool {
	for _, t := range q.Terms {
		matched := false
		if t.Field != "" {
			actual := getFieldValue(f, t.Field)
			for _, v := range t.Values {
				if v.IsWildcard {
					if strings.HasPrefix(strings.ToLower(actual), strings.ToLower(v.Prefix)) {
						matched = true
						break
					}
				} else if strings.EqualFold(actual, v.Raw) {
					matched = true
					break
				}
			}
		} else if t.Text != "" {
			matched = matchFreeText(f, t.Text)
		}

		if t.Negated && matched {
			return false
		}
		if !t.Negated && !matched {
			return false
		}
	}
	return true
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
	case "app":
		return f.ApplicationID.String()
	case "asset":
		return f.AssetID.String()
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
