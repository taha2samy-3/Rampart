package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
)

// FeedItemResponse represents one threat intelligence feed and its live status.
type FeedItemResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	URL         string `json:"url"`
	IsMirror    bool   `json:"is_mirror"`
	Enabled     bool   `json:"enabled"`
	// DisabledReason says why a feed that is not enabled is not run: switched_off (the ClusterFeed says so), egress_denied
	// (egress is deny and it has no mirror address), no_ecosystem (OSV needs one), server_disabled (the server's own
	// configuration). Empty when the feed runs.
	DisabledReason string     `json:"disabled_reason,omitempty"`
	Status         string     `json:"status"` // success | syncing | queued | idle | error | disabled
	Records        int64      `json:"records"`
	LastSync       *time.Time `json:"last_sync,omitempty"`
	Error          *string    `json:"error,omitempty"`
}

// FeedsListResponse is the payload for GET /api/v1/feeds.
type FeedsListResponse struct {
	Mirror *domain.FeedMirrorSpec `json:"mirror,omitempty"`
	Items  []FeedItemResponse     `json:"items"`
}

// FeedTestResult represents the real-time connectivity status of an upstream feed.
type FeedTestResult struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Reachable  bool   `json:"reachable"`
	StatusCode int    `json:"status_code"`
	LatencyMs  int64  `json:"latency_ms"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// FeedTestConnectionResponse is the payload returned by POST /api/v1/feeds/test-connection.
type FeedTestConnectionResponse struct {
	TestedAt time.Time        `json:"tested_at"`
	Results  []FeedTestResult `json:"results"`
}

// FeedSyncResponse represents the response when an on-demand feed synchronization is triggered.
type FeedSyncResponse struct {
	Status    string    `json:"status"` // started | completed
	Feed      string    `json:"feed"`   // "all" or specific feed name
	Message   string    `json:"message"`
	StartedAt time.Time `json:"started_at"`
}

const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	defaultNVDURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultOSVURL  = "https://osv-vulnerabilities.storage.googleapis.com"

	defaultVulnrichmentURL = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"
	defaultExploitDBURL    = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	defaultMetasploitURL   = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
	defaultEUVDURL         = "https://euvdservices.enisa.europa.eu"
	defaultVulnCheckURL    = "https://api.vulncheck.com"
)

// handleListFeeds handles GET /api/v1/feeds (docs/16 D86, D88).
// Returns the active ClusterFeedMirror configuration and the synchronization state of all feeds.
func (a *API) handleListFeeds(w http.ResponseWriter, r *http.Request) {
	if _, err := a.resolveTenant(r); err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	mirror, items, err := a.getFeedItemsAndMirror(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to retrieve feeds: "+err.Error())
		return
	}

	// Any signed-in user reads this page. Where a token is read from is a fact about the server, so it is not sent.
	writeJSON(w, http.StatusOK, FeedsListResponse{
		Mirror: mirror.Redacted(),
		Items:  items,
	})
}

// handleTestFeedsConnection performs live reachability probes against upstream threat intelligence endpoints.
//
// It makes the server call the feed addresses, which are the platform's and not the caller's, so it is for an
// administrator, as the sync is; a viewer of any tenant could otherwise use it to probe the networks the server sees.
func (a *API) handleTestFeedsConnection(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireRole(w, r, auth.RoleAdmin); !ok {
		return
	}

	requestedFeed := strings.TrimSpace(r.URL.Query().Get("feed"))
	if requestedFeed == "" && r.Method == http.MethodPost {
		var req struct {
			Feed string `json:"feed"`
		}
		if raw, rerr := io.ReadAll(io.LimitReader(r.Body, 16<<10)); rerr == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &req)
			requestedFeed = strings.TrimSpace(req.Feed)
		}
	}

	_, items, err := a.getFeedItemsAndMirror(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to retrieve feed configurations: "+err.Error())
		return
	}

	var results []FeedTestResult
	for _, it := range items {
		if requestedFeed != "" && it.Name != requestedFeed {
			continue
		}
		if !it.Enabled {
			results = append(results, FeedTestResult{
				Name:       it.Name,
				URL:        it.URL,
				Reachable:  false,
				StatusCode: 0,
				LatencyMs:  0,
				Message:    "Feed is disabled (air-gapped / egress deny policy)",
			})
			continue
		}
		results = append(results, probeFeedURL(r.Context(), a.feedProbeClient(), it.Name, it.URL))
	}

	if requestedFeed != "" && len(results) == 0 {
		problem(w, http.StatusNotFound, "not-found", "Feed "+requestedFeed+" not found")
		return
	}

	writeJSON(w, http.StatusOK, FeedTestConnectionResponse{
		TestedAt: time.Now().UTC(),
		Results:  results,
	})
}

// FeedSyncer starts an on-demand sync. The implementation runs with the system role (enrich.OnDemand).
type FeedSyncer interface {
	Start(ctx context.Context, feed string, names []string) error
}

// FeedExplainer says why the server's configuration does not run a feed ("" when it does). enrich.OnDemand implements it.
type FeedExplainer interface {
	Why(ctx context.Context, feed string) string
}

// SetFeedSyncer wires the on-demand sync. Without it (no database.systemUrl, or feeds off) the sync button answers 501.
func (a *API) SetFeedSyncer(f FeedSyncer) { a.feedSync = f }

// handleSyncFeeds handles POST /api/v1/feeds/sync[?feed=name]: starts a sync of one feed or of all that are on. It
// answers 202 once the feeds are marked "syncing"; GET /api/v1/feeds then shows the state until it ends.
//
// KNOWN PROBLEM (D125, left as it is on purpose): the feeds are global, but any administrator of any tenant may start this
// sync. There is no platform-administrator role and no cooldown, so in a multi-tenant installation one tenant's
// administrator can start upstream traffic, a re-key and a re-score of every tenant, as often as the lock allows.
func (a *API) handleSyncFeeds(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireRole(w, r, auth.RoleAdmin); !ok { // the feeds are global: one tenant's click syncs for all
		return
	}
	requestedFeed := strings.TrimSpace(r.URL.Query().Get("feed"))
	if requestedFeed == "" && r.Method == http.MethodPost {
		var req struct {
			Feed string `json:"feed"`
		}
		if raw, rerr := io.ReadAll(io.LimitReader(r.Body, 16<<10)); rerr == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &req)
			requestedFeed = strings.TrimSpace(req.Feed)
		}
	}
	if a.feedSync == nil {
		problem(w, http.StatusNotImplemented, "unsupported", "This server cannot sync feeds: it needs feeds.enabled and database.systemUrl")
		return
	}
	_, items, err := a.getFeedItemsAndMirror(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to retrieve feeds: "+err.Error())
		return
	}
	var names []string
	for _, it := range items {
		if !it.Enabled {
			if it.Name == requestedFeed {
				problem(w, http.StatusConflict, "feed-disabled", feedOffMessage(requestedFeed, it.DisabledReason))
				return
			}
			continue
		}
		names = append(names, it.Name)
	}
	if requestedFeed != "" && !containsStr(names, requestedFeed) {
		problem(w, http.StatusNotFound, "not-found", "Feed "+requestedFeed+" not found")
		return
	}
	if err := a.feedSync.Start(r.Context(), requestedFeed, names); err != nil {
		if errors.Is(err, enrich.ErrFeedOff) {
			problem(w, http.StatusConflict, "feed-off", feedOffMessage(requestedFeed, enrich.FeedOffServerConfig))
			return
		}
		if errors.Is(err, enrich.ErrSyncBusy) {
			problem(w, http.StatusConflict, "sync-running", "A feed sync is already running; its progress is in the table")
			return
		}
		problem(w, http.StatusInternalServerError, "internal", "Could not start the sync: "+err.Error())
		return
	}
	target := "all"
	if requestedFeed != "" {
		target = requestedFeed
	}
	writeJSON(w, http.StatusAccepted, FeedSyncResponse{Status: "started", Feed: target, Message: "Sync started", StartedAt: time.Now().UTC()})
}

func (a *API) getFeedItemsAndMirror(ctx context.Context) (*domain.FeedMirrorSpec, []FeedItemResponse, error) {
	mirror, err := a.store.GetClusterFeedMirror(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting cluster feed mirror: %w", err)
	}

	states, err := a.store.ListFeedStates(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("listing feed states: %w", err)
	}

	stateMap := make(map[string]domain.FeedState, len(states))
	for _, st := range states {
		stateMap[st.Feed] = st
	}

	isDeny := mirror != nil && mirror.Egress == "deny"
	explainer, _ := a.feedSync.(FeedExplainer)

	// why is the reason a built-in feed is not run: the ClusterFeed's own switch first, then the egress rule, then what only
	// the server's configuration decides (NVD switched off, OSV with no ecosystem).
	why := func(name, mirrorURL string, enabled *bool) string {
		switch {
		case !domain.On(enabled):
			return enrich.FeedOffSwitched
		case isDeny && mirrorURL == "":
			return enrich.FeedOffEgress
		case explainer != nil:
			return explainer.Why(ctx, name)
		}
		return ""
	}
	// source reads the address and the switch of a built-in feed from the ClusterFeed.
	source := func(src *domain.FeedMirrorSource) (url string, enabled *bool) {
		if src != nil {
			return src.URL, src.Enabled
		}
		return "", nil
	}
	pick := func(url, fallback string) (string, bool) {
		if url != "" {
			return url, true
		}
		return fallback, false
	}

	items := make([]FeedItemResponse, 0, 8)

	kevMirror, kevOn := source(mirrorKEV(mirror))
	kevURL, kevIsMirror := pick(kevMirror, defaultKEVURL)
	items = append(items, buildFeedItem("cisa_kev", "CISA KEV", "Threat Intelligence",
		"Known Exploited Vulnerabilities catalog published by CISA tracking actively exploited CVEs.",
		kevURL, kevIsMirror, why("cisa_kev", kevMirror, kevOn), stateMap["cisa_kev"]))

	epssMirror, epssOn := source(mirrorEPSS(mirror))
	epssURL, epssIsMirror := pick(epssMirror, defaultEPSSURL)
	items = append(items, buildFeedItem("first_epss", "FIRST EPSS", "Exploit Prediction",
		"Exploit Prediction Scoring System probabilities estimating likelihood of active exploitation.",
		epssURL, epssIsMirror, why("first_epss", epssMirror, epssOn), stateMap["first_epss"]))

	var nvdMirror string
	var nvdOn *bool
	if mirror != nil {
		if mirror.NVD != nil {
			nvdMirror = mirror.NVD.URL
		}
		on := mirror.NVD.On() // opt-in: an absent block is off
		nvdOn = &on
	}
	nvdURL, nvdIsMirror := pick(nvdMirror, defaultNVDURL)
	items = append(items, buildFeedItem("nvd", "NVD (National Vulnerability Database)", "Vulnerability Database",
		"NIST National Vulnerability Database CVE records, CVSS severity metrics, and CWE mappings.",
		nvdURL, nvdIsMirror, why("nvd", nvdMirror, nvdOn), stateMap["nvd"]))

	var osvMirror string
	var osvOn *bool
	if mirror != nil && mirror.OSV != nil {
		osvMirror, osvOn = mirror.OSV.URL, mirror.OSV.Enabled
	}
	osvURL, osvIsMirror := pick(osvMirror, defaultOSVURL)
	items = append(items, buildFeedItem("osv", "OSV (Open Source Vulnerabilities)", "Package Advisories",
		"Open Source Vulnerabilities database covering open-source package registries and ecosystems.",
		osvURL, osvIsMirror, why("osv", osvMirror, osvOn), stateMap["osv"]))

	// 2. Optional sources declared in mirror
	if mirror != nil {
		if mirror.Vulnrichment != nil {
			u := mirror.Vulnrichment.URL
			if u == "" {
				u = defaultVulnrichmentURL
			}
			items = append(items, buildFeedItem("vulnrichment", "CISA Vulnrichment (ADP)", "Threat Intelligence",
				"CISA Authorized Data Publisher enriched CVE data, SSVC assessments, and missing CVSS scores.",
				u, mirror.Vulnrichment.URL != "", sourceOff(mirror.Vulnrichment.Off()), stateMap["vulnrichment"]))
		}
		if mirror.ExploitDB != nil {
			u := mirror.ExploitDB.URL
			if u == "" {
				u = defaultExploitDBURL
			}
			items = append(items, buildFeedItem("exploitdb", "Exploit Database", "Public Exploits",
				"Public exploit code repository tracking verified proof-of-concept exploits.",
				u, mirror.ExploitDB.URL != "", sourceOff(mirror.ExploitDB.Off()), stateMap["exploitdb"]))
		}
		if mirror.Metasploit != nil {
			u := mirror.Metasploit.URL
			if u == "" {
				u = defaultMetasploitURL
			}
			items = append(items, buildFeedItem("metasploit", "Metasploit Framework", "Weaponized Modules",
				"Rapid7 Metasploit Framework database of weaponized exploitation modules.",
				u, mirror.Metasploit.URL != "", sourceOff(mirror.Metasploit.Off()), stateMap["metasploit"]))
		}
		if mirror.EUVD != nil {
			u := mirror.EUVD.URL
			if u == "" {
				u = defaultEUVDURL
			}
			items = append(items, buildFeedItem("euvd", "EUVD (ENISA)", "European Intelligence",
				"European Union Vulnerability Database tracking vulnerabilities and European exploitation.",
				u, mirror.EUVD.URL != "", sourceOff(mirror.EUVD.Off()), stateMap["euvd"]))
		}
		if mirror.VulnCheckKEV != nil {
			u := mirror.VulnCheckKEV.URL
			if u == "" {
				u = defaultVulnCheckURL
			}
			items = append(items, buildFeedItem("vulncheck_kev", "VulnCheck KEV", "Threat Intelligence",
				"VulnCheck Known Exploited Vulnerabilities catalog with commercial/community intelligence.",
				u, mirror.VulnCheckKEV.URL != "", sourceOff(mirror.VulnCheckKEV.Off()), stateMap["vulncheck_kev"]))
		}

		// 3. Custom feeds
		for _, c := range mirror.Custom {
			feedType := "Custom Pull"
			targetURL := c.URL
			if c.PushTokenFile != "" {
				feedType = "Custom Push"
				targetURL = "/api/v1/feeds/" + c.Name
			}
			items = append(items, buildFeedItem(c.Name, strings.ToUpper(c.Name), feedType,
				"Custom in-house or licensed threat intelligence feed ("+c.Format+" format).",
				targetURL, true, sourceOff(c.Off()), stateMap[c.Name]))
		}
	}

	return mirror, items, nil
}

// SetFeedProbeClient replaces the client of the connection test (tests that serve a feed from 127.0.0.1).
func (a *API) SetFeedProbeClient(c *http.Client) { a.probeClient = c }

func (a *API) feedProbeClient() *http.Client {
	if a.probeClient != nil {
		return a.probeClient
	}
	return enrich.NewFeedHTTPClient(6*time.Second, false)
}

func probeFeedURL(ctx context.Context, client *http.Client, name, targetURL string) FeedTestResult {
	start := time.Now()
	res := FeedTestResult{
		Name: name,
		URL:  redactFeedURL(targetURL),
	}

	if targetURL == "" || strings.HasPrefix(targetURL, "/") {
		res.Reachable = true
		res.StatusCode = 200
		res.LatencyMs = 0
		res.Message = "Local API endpoint / Push feed ready"
		return res
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		res.Error = "the address is not a valid URL"
		res.Message = "Failed to construct request"
		return res
	}
	req.Header.Set("User-Agent", "Rampart-FeedProbe/1.0")

	resp, err := client.Do(req)
	// Some endpoints reject HEAD (like 405 Method Not Allowed, 403 Forbidden, 400 Bad Request), retry with small range GET
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadRequest) {
		_ = resp.Body.Close()
		getReq, gerr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if gerr == nil {
			getReq.Header.Set("User-Agent", "Rampart-FeedProbe/1.0")
			getReq.Header.Set("Range", "bytes=0-1024")
			if gresp, err2 := client.Do(getReq); err2 == nil {
				resp = gresp
				err = nil
			}
		}
	}

	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Message = "Connection failed: " + err.Error()
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	res.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.Reachable = true
		res.Message = fmt.Sprintf("Upstream reachable (HTTP %d OK)", resp.StatusCode)
	} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
		res.Reachable = true
		res.Message = fmt.Sprintf("Upstream reachable, but rate-limited (HTTP %d)", resp.StatusCode)
	} else {
		res.Message = fmt.Sprintf("Upstream responded with HTTP %d", resp.StatusCode)
	}
	return res
}

func redactFeedURL(raw string) string { return domain.RedactFeedURL(raw) }

func buildFeedItem(name, displayName, category, description, targetURL string, isMirror bool, disabledReason string, st domain.FeedState) FeedItemResponse {
	enabled := disabledReason == ""
	status := "idle"
	if !enabled {
		status = "disabled"
	} else if st.Status != "" {
		status = st.Status
	}

	return FeedItemResponse{
		Name:           name,
		DisplayName:    displayName,
		Category:       category,
		Description:    description,
		URL:            redactFeedURL(targetURL),
		IsMirror:       isMirror,
		Enabled:        enabled,
		DisabledReason: disabledReason,
		Status:         status,
		Records:        st.Records,
		LastSync:       st.LastSync,
		Error:          st.Error,
	}
}

// sourceOff is the reason of an optional or custom source: only its own switch can turn it off.
func sourceOff(off bool) string {
	if off {
		return enrich.FeedOffSwitched
	}
	return ""
}

func mirrorKEV(m *domain.FeedMirrorSpec) *domain.FeedMirrorSource {
	if m == nil {
		return nil
	}
	return m.KEV
}

func mirrorEPSS(m *domain.FeedMirrorSpec) *domain.FeedMirrorSource {
	if m == nil {
		return nil
	}
	return m.EPSS
}

// feedOffMessage says, in a sentence, why a feed that was asked for is not run.
func feedOffMessage(name, reason string) string {
	switch reason {
	case enrich.FeedOffSwitched:
		return "Feed " + name + " is switched off in the ClusterFeed (enabled: false)"
	case enrich.FeedOffEgress:
		return "Feed " + name + " is not read: egress is denied and the ClusterFeed gives it no mirror address"
	case enrich.FeedOffNoEcosystem:
		return "Feed " + name + " has no ecosystem chosen: name one in the ClusterFeed (osv.ecosystems) or in feeds.osvEcosystems"
	case enrich.FeedOffServerConfig:
		return "Feed " + name + " is switched off in the server's configuration (feeds.nvdDisabled)"
	}
	return "Feed " + name + " is switched off"
}
