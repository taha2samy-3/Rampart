package query

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"rampart/internal/query/sqlbuilder"
	"rampart/internal/scoring"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/graph"
	"rampart/internal/ingest"
	"rampart/internal/objectstore"
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
	ssrfAllowlist  *domain.PlatformSSRFAllowlist
	store          store.Store
	feeds          *enrich.FeedStore
	feedSync       FeedSyncer
	pushTokenDir   string       // where a feed plugin's token file may be; empty is domain.FeedPushTokensDir (tests set a temp directory)
	probeClient    *http.Client // the connection test of the feeds page; nil is the guarded feed client (enrich.NewFeedHTTPClient)
	authn          *auth.Authenticator
	hmacKey        []byte
	objects        objectstore.Store
	intel          IntelSource
	logos          logoCache
	scorer         *scoring.Scorer
	gw             *ingest.Gateway
	live           *LiveHub
	analyzerProbe  AnalyzerProbe      // how an external analyzer is tested; nil dials it over gRPC
	trackerProbe   TrackerProbe       // how an external tracker container is tested; nil dials it over gRPC
	analysis       AnalysisDispatcher // queues the analysis of SBOMs; nil when analysis is switched off
	maxInFlight    int                // max in-flight analyses across all tenants (docs/39 Slice D)
	manualCooldown time.Duration      // minimum cooldown between manual analyses of an application (docs/39 Slice D)
}

// FindingQuerier is implemented by stores that run the filter grammar as SQL (PostgreSQL). Other
// stores (the in-memory one used by tests) fall back to filtering in memory.
type FindingQuerier interface {
	QueryFindings(ctx context.Context, tenantID uuid.UUID, q *grammar.Query, sortKey string, limit int, cur *sqlbuilder.Cursor) ([]*domain.Finding, error)
	CountFindings(ctx context.Context, tenantID uuid.UUID, q *grammar.Query) (int, error)
}

// IntelSource looks up KEV and EPSS data for vulnerability ids (PostgreSQL: the global vulnerability
// table that the feed sync fills).
type IntelSource interface {
	Lookup(ctx context.Context, ids []string) (*enrich.FeedStore, error)
}

// SetIntelSource makes the API read threat intelligence from the database, per page, instead of from the
// in-memory feed store.
func (a *API) SetIntelSource(src IntelSource) { a.intel = src }

// feedsFor returns the feed data to score findings with the given vulnerability ids.
func (a *API) feedsFor(ctx context.Context, ids []string) *enrich.FeedStore {
	if a.intel == nil || len(ids) == 0 {
		return a.feeds
	}
	fs, err := a.intel.Lookup(ctx, ids)
	if err != nil {
		slog.Warn("threat intelligence lookup failed; scoring without it", "error", err)
		return a.feeds
	}
	return fs
}

// SetScorer makes the API explain scores with the same inputs that are stored (application context, no age
// factor, D28) and report the stored SLA.
func (a *API) SetScorer(s *scoring.Scorer) { a.scorer = s }

// breakdown is the explainable score of a finding for the response.
func (a *API) breakdown(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, vulnIDs []string, feeds *enrich.FeedStore, apps map[uuid.UUID]*domain.Application) risk.ScoreBreakdown {
	if a.scorer != nil {
		return a.scorer.Explain(ctx, tenantID, f, feeds, apps)
	}
	// Without a scorer (the in-memory store): the built-in policy, without application context (D62).
	_ = vulnIDs
	b, _ := scoring.Breakdown(f, nil, feeds, nil)
	return b
}

// slaDue is the stored due date of an active finding, or the built-in policy's when it has not been stored.
func slaDue(f *domain.Finding, band domain.Severity) *time.Time {
	if f.SLADue != nil {
		return f.SLADue
	}
	d := risk.CalculateSLADueDate(band, "low", f.FirstSeen, nil)
	return &d
}

// SetObjectStore gives the API the store the raw reports are in, so a run's report can be downloaded.
func (a *API) SetObjectStore(o objectstore.Store) { a.objects = o }

// SetCursorKey sets the key that signs pagination cursors (D16). Without one, each process uses a random
// key, so a cursor never outlives the process that issued it.
func (a *API) SetCursorKey(key []byte) { a.hmacKey = append([]byte(nil), key...) }

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
		store:          s,
		feeds:          feeds,
		authn:          authn,
		hmacKey:        randomKey(),
		maxInFlight:    50,
		manualCooldown: 5 * time.Minute,
	}
}

func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("query: no randomness for the cursor key: " + err.Error())
	}
	return k
}

// RegisterRoutes mounts all /api/v1 routes onto the router.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	// Every route goes through ingestOnlyGuard (D80): a CI ingest token reaches only the gate.
	routes := &guardedMux{ServeMux: mux, guard: a.ingestOnlyGuard}
	routes.HandleFunc("GET /api/v1/findings", a.handleListFindings)
	routes.HandleFunc("GET /api/v1/findings/{id}", a.handleGetFinding)
	routes.HandleFunc("PATCH /api/v1/findings/{id}", a.handlePatchFinding)
	routes.HandleFunc("POST /api/v1/findings/bulk", a.handleBulkTriage)
	routes.HandleFunc("GET /api/v1/findings/{id}/events", a.handleFindingEvents)
	routes.HandleFunc("POST /api/v1/gate", a.handleGate) // D26
	routes.HandleFunc("POST /api/v1/risk-acceptances", a.handleRequestAcceptance)
	routes.HandleFunc("GET /api/v1/risk-acceptances", a.handleListAcceptances)
	routes.HandleFunc("GET /api/v1/risk-acceptances/{id}", a.handleGetAcceptance)
	routes.HandleFunc("POST /api/v1/risk-acceptances/{id}/approve", a.decide("approve"))
	routes.HandleFunc("POST /api/v1/risk-acceptances/{id}/reject", a.decide("reject"))
	routes.HandleFunc("POST /api/v1/risk-acceptances/{id}/revoke", a.decide("revoke"))
	routes.HandleFunc("POST /api/v1/risk-acceptances/{id}/proofs", a.handleAddProof)
	routes.HandleFunc("GET /api/v1/risk-acceptances/{id}/proofs", a.handleListProofs)
	routes.HandleFunc("GET /api/v1/risk-acceptances/{id}/proofs/{proof}", a.handleGetProof)
	routes.HandleFunc("GET /api/v1/settings", a.handleGetSettings)
	routes.HandleFunc("PATCH /api/v1/settings", a.handlePatchSettings)
	routes.HandleFunc("GET /api/v1/applications", a.handleListApplications)
	routes.HandleFunc("GET /api/v1/applications/{id}/summary", a.handleApplicationSummary)
	routes.HandleFunc("GET /api/v1/applications/{id}/trend", a.handleApplicationTrend)
	routes.HandleFunc("GET /api/v1/hierarchy", a.handleListHierarchy)
	routes.HandleFunc("GET /api/v1/dashboards/overview", a.handleOverview)
	routes.HandleFunc("GET /api/v1/notifications", a.handleListNotifications)
	routes.HandleFunc("POST /api/v1/notifications/read", a.handleReadNotifications)
	routes.HandleFunc("GET /api/v1/audit", a.handleListAudit)
	routes.HandleFunc("GET /api/v1/inventory", a.handleInventoryAssets)
	routes.HandleFunc("GET /api/v1/inventory/components", a.handleInventoryComponents)
	routes.HandleFunc("POST /api/v1/inventory/components/scan", a.handleScanComponent)
	routes.HandleFunc("GET /api/v1/vulnerabilities/{id}", a.handleGetVulnerability)
	routes.HandleFunc("POST /api/v1/vulnerabilities/{id}/refresh", a.handleRefreshVulnerability)
	routes.HandleFunc("GET /api/v1/vulnerabilities/{id}/impact", a.handleVulnerabilityImpact)
	routes.HandleFunc("GET /api/v1/taxonomies", a.handleListTaxonomies)
	routes.HandleFunc("GET /api/v1/taxonomies/{id}/status", a.handleTaxonomyStatus)
	routes.HandleFunc("GET /api/v1/applications/{id}/compliance", a.handleApplicationCompliance)
	routes.HandleFunc("GET /api/v1/applications/{id}/changes", a.handleApplicationChanges)
	routes.HandleFunc("GET /api/v1/taxonomies/{id}/logo", a.handleTaxonomyLogo)
	routes.HandleFunc("GET /api/v1/taxonomies/{id}/history", a.handleTaxonomyHistory)                 // the days a reading was kept (D102)
	routes.HandleFunc("POST /api/v1/taxonomies/{id}/controls/{control}/attestations", a.handleAttest) // a manual control (D102)
	routes.HandleFunc("GET /api/v1/runs/{id}/report", a.handleRunReport)
	routes.HandleFunc("GET /api/v1/access-bindings", a.handleListBindings)
	routes.HandleFunc("POST /api/v1/access-bindings", a.handleCreateBinding)
	routes.HandleFunc("DELETE /api/v1/access-bindings/{id}", a.handleDeleteBinding)
	routes.HandleFunc("GET /api/v1/me/access", a.handleMyAccess)
	routes.HandleFunc("GET /api/v1/metrics/trend", a.handleTrend)
	routes.HandleFunc("GET /api/v1/runs", a.handleListRuns)
	routes.HandleFunc("GET /api/v1/runs/{id}", a.handleGetRun)
	routes.HandleFunc("GET /api/v1/assets/{id}/sbom", a.handleGetAssetSBOM)
	routes.HandleFunc("GET /api/v1/applications/{id}/sbom", a.handleApplicationSBOM) // merged, CycloneDX or SPDX (doc 11, D95)
	routes.HandleFunc("GET /api/v1/applications/{id}/components", a.handleApplicationComponents)
	routes.HandleFunc("PATCH /api/v1/applications/{id}", a.handleUpdateApplicationContext) // what the score knows about it (D136)
	routes.HandleFunc("GET /api/v1/scoring", a.handleScoring)                              // the version and what decides a score (D136)
	routes.HandleFunc("GET /api/v1/assets/{id}/sbom/graph", a.handleGetAssetSBOMGraph)
	routes.HandleFunc("GET /api/v1/applications/{id}/sbom/graph", a.handleGetAssetSBOMGraph)
	routes.HandleFunc("GET /api/v1/assets/{id}/sbom/path", a.handleGetAssetSBOMPath)
	routes.HandleFunc("GET /api/v1/applications/{id}/sbom/path", a.handleGetAssetSBOMPath)
	routes.HandleFunc("GET /api/v1/assets/{id}/vex", a.handleExportVEX)
	routes.HandleFunc("GET /api/v1/applications/{id}/vex", a.handleExportVEX)
	routes.HandleFunc("POST /api/v1/vex", a.handleImportVEX)
	routes.HandleFunc("POST /api/v1/uploads", a.handleCreateUpload)
	routes.HandleFunc("POST /api/v1/uploads/{id}/complete", a.handleCompleteUpload)
	routes.HandleFunc("POST /api/v1/uploads/direct", a.handleDirectUpload)
	routes.HandleFunc("GET /api/v1/held-closes", a.handleListHeldCloses)
	routes.HandleFunc("POST /api/v1/held-closes/{id}/confirm", a.handleConfirmHeldClose)
	routes.HandleFunc("POST /api/v1/held-closes/{id}/discard", a.handleDiscardHeldClose)

	// Saved views & finding groups (docs/21 §6.1, §6.2)
	routes.HandleFunc("GET /api/v1/views", a.handleListViews)
	routes.HandleFunc("POST /api/v1/views", a.handleCreateView)
	routes.HandleFunc("DELETE /api/v1/views/{id}", a.handleDeleteView)
	routes.HandleFunc("GET /api/v1/groups", a.handleListGroups)
	routes.HandleFunc("POST /api/v1/groups", a.handleCreateGroup)
	routes.HandleFunc("GET /api/v1/groups/{id}", a.handleGetGroup)
	routes.HandleFunc("DELETE /api/v1/groups/{id}", a.handleDeleteGroup)
	routes.HandleFunc("POST /api/v1/groups/{id}/members", a.handleAddGroupMembers)
	routes.HandleFunc("DELETE /api/v1/groups/{id}/members", a.handleRemoveGroupMembers)
	routes.HandleFunc("POST /api/v1/groups/{id}/ticket", a.handleGroupTicket)

	// Exports & Live SSE (docs/21 §6.3, §6.4)
	routes.HandleFunc("GET /api/v1/findings/export", a.handleExportFindings)
	routes.HandleFunc("GET /api/v1/stream", a.handleStream)

	// Parsers catalogue & descriptors (docs/19 §2, docs/13 §9)
	routes.HandleFunc("GET /api/v1/parsers", a.handleListParsers)
	routes.HandleFunc("GET /api/v1/analyzers", a.handleListAnalyzers)
	routes.HandleFunc("GET /api/v1/analyzers/events", a.handleAnalyzerEvents)
	routes.HandleFunc("POST /api/v1/analyzers/test", a.handleTestAnalyzer)
	routes.HandleFunc("POST /api/v1/analyzers/analyze", a.handleAnalyzeWithAnalyzer)
	routes.HandleFunc("POST /api/v1/assets/{id}/analyze", a.handleAnalyzeAsset)

	// External ticketing containers & ticket queue (docs/49)
	routes.HandleFunc("GET /api/v1/trackers", a.handleListTrackers)
	routes.HandleFunc("GET /api/v1/trackers/events", a.handleTrackerEvents)
	routes.HandleFunc("POST /api/v1/trackers/test", a.handleTestTracker)
	routes.HandleFunc("GET /api/v1/tickets", a.handleListTickets)

	// Connectors are resources (D82): listed, described and validated here, never created.
	routes.HandleFunc("GET /api/v1/connectors", a.handleListConnectors)
	routes.HandleFunc("GET /api/v1/connectors/catalogue", a.handleConnectorCatalogue)
	routes.HandleFunc("GET /api/v1/integration-packages", a.handleListPackages)
	routes.HandleFunc("GET /api/v1/feeds", a.handleListFeeds)
	routes.HandleFunc("POST /api/v1/feeds/test-connection", a.handleTestFeedsConnection)
	routes.HandleFunc("GET /api/v1/feeds/test-connection", a.handleTestFeedsConnection)
	routes.HandleFunc("POST /api/v1/feeds/sync", a.handleSyncFeeds)
	routes.HandleFunc("POST /api/v1/attestation-tickets/{id}/retry", a.handleRetryAttestationTicket)
	routes.HandleFunc("POST /api/v1/applications/{id}/refresh-vulnerabilities", a.handleRefreshVulnerabilities)
	routes.HandleFunc("GET /api/v1/applications/{id}/freshness", a.handleApplicationFreshness)
	routes.HandleFunc("GET /api/v1/applications/{id}/sources", a.handleApplicationSources)
	routes.HandleFunc("POST /api/v1/feeds/{name}", a.handleFeedPush)
	routes.HandleFunc("POST /api/v1/connectors/validate", a.handleValidateConnector)

	routes.HandleFunc("GET /api/v1/openapi.json", a.handleOpenAPI)
	routes.HandleFunc("GET /openapi.json", a.handleOpenAPI)
}

// FindingResponse wraps a finding with its calculated risk and SLA details.
type FindingResponse struct {
	Finding     *domain.Finding      `json:"finding"`
	Risk        risk.ScoreBreakdown  `json:"risk"`
	SLADueDate  *time.Time           `json:"sla_due_date,omitempty"`
	Occurrences []*domain.Occurrence `json:"occurrences,omitempty"`
	// ReportedBy folds the occurrences by tool: who reported this finding, since when, and whether each still does.
	ReportedBy []Reporter `json:"reported_by"`
	// AlsoReportedBy lists findings of other tools that share this finding's correlation key (D24).
	AlsoReportedBy []CorrelatedRef `json:"also_reported_by,omitempty"`
	// Controls are the compliance controls this open finding counts against, in the frameworks that read its application
	// (only on GET /findings/{id}): fix it before its deadline and these controls do not go out of compliance.
	Controls []FindingControl `json:"controls"`
}

// CorrelatedRef points at a finding in the same correlation group.
type CorrelatedRef struct {
	ID      uuid.UUID `json:"id"`
	Scanner string    `json:"scanner"`
	RuleID  string    `json:"rule_id"`
	State   string    `json:"state"`
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

// meOf is who "me" is: the caller's e-mail, or a token's subject when that is an e-mail (D48 matches subjects the
// same way), or "".
func meOf(u *auth.ContextUser) string {
	if u == nil {
		return ""
	}
	if u.Email != "" {
		return strings.ToLower(u.Email)
	}
	if strings.Contains(u.Subject, "@") {
		return strings.ToLower(u.Subject)
	}
	return ""
}

// callerEmail is meOf for the request's caller.
func (a *API) callerEmail(r *http.Request) string {
	if u, ok := auth.FromContext(r.Context()); ok && u != nil {
		return meOf(u)
	}
	if a.authn != nil {
		if u, err := a.authn.AuthenticateRequest(r); err == nil && u != nil {
			return meOf(u)
		}
	}
	return ""
}

// expandMe replaces owner:me with the caller's e-mail ("My work", docs/13). A caller without an e-mail owns
// nothing, so the term matches nothing rather than being dropped (D59).
func expandMe(q *grammar.Query, email string) {
	if q == nil {
		return
	}
	for i := range q.Terms {
		if q.Terms[i].Field != "owner" {
			continue
		}
		for j := range q.Terms[i].Values {
			if strings.EqualFold(q.Terms[i].Values[j].Raw, "me") {
				if email == "" {
					email = "\x00no-owner"
				}
				q.Terms[i].Values[j].Raw = email
			}
		}
	}
}

func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

	// 1. Parse the filter ?q= and the sort.
	qParam := r.URL.Query().Get("q")
	var parsedQuery *grammar.Query
	if qParam != "" {
		pq, err := grammar.Parse(qParam)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid query syntax: %v"}`, err), http.StatusBadRequest)
			return
		}
		parsedQuery = &pq
		expandMe(parsedQuery, a.callerEmail(r))
	}
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "-score"
	}
	limit := DefaultLimit
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsedL, err := strconv.Atoi(lStr); err == nil && parsedL > 0 {
			limit = parsedL
			if limit > MaxLimit {
				limit = MaxLimit
			}
		}
	}
	cursorParam := r.URL.Query().Get("cursor")

	var page []*domain.Finding
	var total int
	nextCursor := ""

	if fq, ok := a.store.(FindingQuerier); ok {
		// 2a. SQL path: filter, sort and keyset pagination run in the database (D16).
		var cur *sqlbuilder.Cursor
		if cursorParam != "" {
			c, err := sqlbuilder.DecodeCursor(cursorParam, a.hmacKey)
			if err != nil || c.SortKey != sortKey || c.Filter != qParam {
				problem(w, http.StatusBadRequest, "validation", "The cursor is invalid or no longer matches the filter or sort")
				return
			}
			cur = c
		}
		rows, err := fq.QueryFindings(r.Context(), tenantID, parsedQuery, sortKey, limit, cur)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to list findings")
			return
		}
		if total, err = fq.CountFindings(r.Context(), tenantID, parsedQuery); err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to count findings")
			return
		}
		if len(rows) > limit { // the extra row only proves there is a next page
			rows = rows[:limit]
			last := rows[len(rows)-1]
			nextCursor = (&sqlbuilder.Cursor{SortKey: sortKey, SortVal: sortValue(sortKey, last), ID: last.ID.String(), Filter: qParam}).Encode(a.hmacKey)
		}
		page = rows
	} else {
		// 2b. In-memory path (tests and development with the in-memory store).
		all, err := a.store.ListFindings(r.Context(), tenantID)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to list findings")
			return
		}
		var filtered []*domain.Finding
		for _, f := range all {
			if parsedQuery != nil && !matchesQuery(f, *parsedQuery) {
				continue
			}
			filtered = append(filtered, f)
		}
		sortFindings(filtered, sortKey)
		offset := 0
		if cursorParam != "" {
			off, err := a.decodeCursor(cursorParam, sortKey, qParam)
			if err != nil {
				problem(w, http.StatusBadRequest, "validation", "The cursor is invalid or no longer matches the filter or sort")
				return
			}
			offset = off
		}
		total = len(filtered)
		start := min(offset, total)
		end := min(start+limit, total)
		page = filtered[start:end]
		if end < total {
			nextCursor = a.encodeCursor(end, sortKey, qParam)
		}
	}

	var pageIDs []string
	for _, f := range page {
		if f.VulnerabilityID != nil {
			pageIDs = append(pageIDs, *f.VulnerabilityID)
		}
	}
	pageFeeds := a.feedsFor(r.Context(), pageIDs)

	apps := map[uuid.UUID]*domain.Application{}
	items := make([]FindingResponse, 0, len(page)) // an empty page is [], not null
	for _, f := range page {
		var vulnIDs []string
		if f.VulnerabilityID != nil {
			vulnIDs = []string{*f.VulnerabilityID}
		}
		riskBreakdown := a.breakdown(r.Context(), tenantID, f, vulnIDs, pageFeeds, apps)
		items = append(items, FindingResponse{Finding: f, Risk: riskBreakdown, SLADueDate: slaDue(f, riskBreakdown.Band)})
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

	riskBreakdown := a.breakdown(r.Context(), tenantID, finding, vulnIDs, a.feedsFor(r.Context(), vulnIDs), map[uuid.UUID]*domain.Application{})
	res := FindingResponse{
		Finding:     finding,
		Risk:        riskBreakdown,
		SLADueDate:  slaDue(finding, riskBreakdown.Band),
		Occurrences: occs,
		ReportedBy:  reportersOf(occs),
	}
	if group, gerr := a.store.ListCorrelated(r.Context(), tenantID, finding.ID); gerr == nil {
		for _, g := range group {
			res.AlsoReportedBy = append(res.AlsoReportedBy, CorrelatedRef{ID: g.ID, Scanner: g.RuleScannerFamily, RuleID: g.RuleID, State: string(g.State)})
		}
	}
	res.Controls = a.findingControls(r.Context(), tenantID, finding, finding.SLADue) // the stored deadline: a built-in fallback would say "12 days left" while the controls already count it (D120)

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

	if r.URL.Query().Has("format") { // a standard document (D95)
		a.exportAssetSBOM(w, r, tenantID, assetID)
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
	targetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid UUID"}`, http.StatusBadRequest)
		return
	}

	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, targetID)
	if (err != nil || sbom == nil) && a.store != nil {
		if lister, ok := a.store.(appAssetLister); ok {
			if assets, lerr := lister.ListApplicationAssets(r.Context(), tenantID, targetID); lerr == nil {
				for _, as := range assets {
					if s, c, gerr := a.store.GetSBOM(r.Context(), tenantID, as.ID); gerr == nil && s != nil {
						sbom, comps = s, c
						break
					}
				}
			}
		}
	}
	if sbom == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"SBOM not found"}`, http.StatusNotFound)
		return
	}

	view := graph.BuildView(comps, sbom.Dependencies, sbom.RootComponent, a.packageRisk(r.Context(), tenantID, sbom))

	// The view's own fields (root, nodes, edges, the counts) sit at the top level of the answer, next to the document's.
	res := struct {
		AssetID         uuid.UUID `json:"asset_id"`
		Format          string    `json:"format"`
		SpecVersion     string    `json:"spec_version"`
		TotalComponents int       `json:"total_components"`
		*graph.View
	}{AssetID: targetID, Format: sbom.Format, SpecVersion: sbom.SpecVersion, TotalComponents: len(view.Nodes), View: view}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// packageRisk returns the function that gives a component of the SBOM its open findings, or nil when the store cannot
// tell (the graph is then drawn without them). A finding is matched on the package url without its version, and on the
// version when the scanner reported one, so two versions of a package in one tree are not given each other's findings.
func (a *API) packageRisk(ctx context.Context, tenantID uuid.UUID, sbom *domain.SBOM) func(domain.SBOMComponent) graph.Risk {
	rd, ok := a.store.(store.PackageRiskReader)
	if !ok || sbom == nil {
		return nil
	}
	rows, err := rd.ListPackageRisk(ctx, tenantID, sbom.AssetID, sbom.Track)
	if err != nil || len(rows) == 0 {
		return nil
	}
	byBase := map[string][]store.PackageRisk{}
	for _, r := range rows {
		byBase[r.PurlBase] = append(byBase[r.PurlBase], r)
	}
	return func(c domain.SBOMComponent) graph.Risk {
		var out graph.Risk
		for _, r := range byBase[c.PurlBase] {
			if r.Version != "" && r.Version != c.Version {
				continue
			}
			out.Critical += r.Critical
			out.High += r.High
			out.Medium += r.Medium
			out.Low += r.Low
		}
		return out
	}
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
	targetID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid UUID"}`, http.StatusBadRequest)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"'target' query parameter is required"}`, http.StatusBadRequest)
		return
	}

	sbom, comps, err := a.store.GetSBOM(r.Context(), tenantID, targetID)
	if (err != nil || sbom == nil) && a.store != nil {
		if lister, ok := a.store.(appAssetLister); ok {
			if assets, lerr := lister.ListApplicationAssets(r.Context(), tenantID, targetID); lerr == nil {
				for _, as := range assets {
					if s, c, gerr := a.store.GetSBOM(r.Context(), tenantID, as.ID); gerr == nil && s != nil {
						sbom, comps = s, c
						break
					}
				}
			}
		}
	}
	if sbom == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"SBOM not found"}`, http.StatusNotFound)
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
		AssetID: targetID,
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

func problem(w http.ResponseWriter, status int, typ, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "https://rampart.aspm.dev/problems/" + typ, "title": title, "status": status})
}

// sortValue is the value of the sort column for the last row of a page, which the next page continues from.
func sortValue(sortKey string, f *domain.Finding) string {
	switch sortKey {
	case "seen", "-seen":
		return f.LastSeen.UTC().Format(time.RFC3339Nano)
	case "age", "-age":
		return f.FirstSeen.UTC().Format(time.RFC3339Nano)
	case "severity":
		return strconv.Itoa(severityRank(f.Severity))
	default:
		return strconv.Itoa(f.RiskScore)
	}
}

func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	}
	return 0
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// guardedMux wraps every handler registered on it with guard.
type guardedMux struct {
	*http.ServeMux
	guard func(pattern string, h http.Handler) http.Handler
}

func (m *guardedMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.ServeMux.Handle(pattern, rejectNUL(m.guard(pattern, http.HandlerFunc(h))))
}

func (m *guardedMux) Handle(pattern string, h http.Handler) {
	m.ServeMux.Handle(pattern, rejectNUL(m.guard(pattern, h)))
}

// rejectNUL answers 400 to a request with a NUL in its query string or body (not a file upload). PostgreSQL stores a NUL in no
// text or jsonb value, so the write that carried it failed and the caller got HTTP 500 "Failed to save the
// decision" for what is a bad request (a note, a tag, a filter with %00 in it).
func rejectNUL(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range r.URL.Query() {
			if strings.ContainsRune(k, 0) || slices.ContainsFunc(vs, func(v string) bool { return strings.ContainsRune(v, 0) }) {
				problem(w, http.StatusBadRequest, "validation", "A NUL character is not allowed in a query parameter")
				return
			}
		}
		if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodPut) &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			head, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			if bytes.IndexByte(head, 0) >= 0 || bytes.Contains(head, []byte{'\\', 'u', '0', '0', '0', '0'}) {
				problem(w, http.StatusBadRequest, "validation", "A NUL character is not allowed in the request")
				return
			}
			rest := r.Body
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(head), rest), rest}
		}
		h.ServeHTTP(w, r)
	})
}

// ingestRoutes are the query-API routes a CI ingest token may call: the gate, which `rampart gate` calls from the
// pipeline with the same token it uploaded with (D26, D37).
var ingestRoutes = map[string]bool{"POST /api/v1/gate": true}

// ingestOnlyGuard refuses a caller whose role is ingest on every other route (D80). An ingest token is for writing
// reports; most read routes check only the tenant, so without this a 15-minute CI token could read every finding of
// the tenant. A request with no credentials or another role passes through untouched.
func (a *API) ingestOnlyGuard(pattern string, h http.Handler) http.Handler {
	if ingestRoutes[pattern] {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u *auth.ContextUser
		if cu, ok := auth.FromContext(r.Context()); ok {
			u = cu
		} else if a.authn != nil && r.Header.Get("Authorization") != "" {
			u, _ = a.authn.AuthenticateRequest(r)
		}
		if u != nil && u.Role == auth.RoleIngest {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/forbidden","title":"An ingest token can only upload reports and call the gate","status":403}`))
			return
		}
		h.ServeHTTP(w, r)
	})
}
