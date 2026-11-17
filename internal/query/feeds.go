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
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	URL         string     `json:"url"`
	IsMirror    bool       `json:"is_mirror"`
	Enabled     bool       `json:"enabled"`
	Status      string     `json:"status"` // success | syncing | idle | error | disabled
	Records     int64      `json:"records"`
	LastSync    *time.Time `json:"last_sync,omitempty"`
	Error       *string    `json:"error,omitempty"`
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

	writeJSON(w, http.StatusOK, FeedsListResponse{
		Mirror: mirror,
		Items:  items,
	})
}

// handleTestFeedsConnection performs live reachability probes against upstream threat intelligence endpoints.
func (a *API) handleTestFeedsConnection(w http.ResponseWriter, r *http.Request) {
	if _, err := a.resolveTenant(r); err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
		results = append(results, probeFeedURL(r.Context(), it.Name, it.URL))
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
				problem(w, http.StatusConflict, "feed-disabled", "Feed "+requestedFeed+" is switched off (egress deny without a mirror)")
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
			problem(w, http.StatusConflict, "feed-off", "This feed is switched off in the server's configuration (NVD disabled, or OSV with no ecosystem chosen)")
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

	// 1. Standard Built-in Feeds
	items := make([]FeedItemResponse, 0, 8)

	// CISA KEV
	kevURL := defaultKEVURL
	kevIsMirror := false
	kevEnabled := true
	if mirror != nil && mirror.KEV != nil && mirror.KEV.URL != "" {
		kevURL = mirror.KEV.URL
		kevIsMirror = true
	} else if isDeny {
		kevEnabled = false
	}
	items = append(items, buildFeedItem("cisa_kev", "CISA KEV", "Threat Intelligence",
		"Known Exploited Vulnerabilities catalog published by CISA tracking actively exploited CVEs.",
		kevURL, kevIsMirror, kevEnabled, stateMap["cisa_kev"]))

	// FIRST EPSS
	epssURL := defaultEPSSURL
	epssIsMirror := false
	epssEnabled := true
	if mirror != nil && mirror.EPSS != nil && mirror.EPSS.URL != "" {
		epssURL = mirror.EPSS.URL
		epssIsMirror = true
	} else if isDeny {
		epssEnabled = false
	}
	items = append(items, buildFeedItem("first_epss", "FIRST EPSS", "Exploit Prediction",
		"Exploit Prediction Scoring System probabilities estimating likelihood of active exploitation.",
		epssURL, epssIsMirror, epssEnabled, stateMap["first_epss"]))

	// NVD
	nvdURL := defaultNVDURL
	nvdIsMirror := false
	nvdEnabled := true
	if mirror != nil && mirror.NVD != nil && mirror.NVD.URL != "" {
		nvdURL = mirror.NVD.URL
		nvdIsMirror = true
	} else if isDeny {
		nvdEnabled = false
	}
	items = append(items, buildFeedItem("nvd", "NVD (National Vulnerability Database)", "Vulnerability Database",
		"NIST National Vulnerability Database CVE records, CVSS severity metrics, and CWE mappings.",
		nvdURL, nvdIsMirror, nvdEnabled, stateMap["nvd"]))

	// OSV
	osvURL := defaultOSVURL
	osvIsMirror := false
	osvEnabled := true
	if mirror != nil && mirror.OSV != nil && mirror.OSV.URL != "" {
		osvURL = mirror.OSV.URL
		osvIsMirror = true
	} else if isDeny {
		osvEnabled = false
	}
	items = append(items, buildFeedItem("osv", "OSV (Open Source Vulnerabilities)", "Package Advisories",
		"Open Source Vulnerabilities database covering open-source package registries and ecosystems.",
		osvURL, osvIsMirror, osvEnabled, stateMap["osv"]))

	// 2. Optional sources declared in mirror
	if mirror != nil {
		if mirror.Vulnrichment != nil {
			u := mirror.Vulnrichment.URL
			if u == "" {
				u = defaultVulnrichmentURL
			}
			items = append(items, buildFeedItem("vulnrichment", "CISA Vulnrichment (ADP)", "Threat Intelligence",
				"CISA Authorized Data Publisher enriched CVE data, SSVC assessments, and missing CVSS scores.",
				u, mirror.Vulnrichment.URL != "", true, stateMap["vulnrichment"]))
		}
		if mirror.ExploitDB != nil {
			u := mirror.ExploitDB.URL
			if u == "" {
				u = defaultExploitDBURL
			}
			items = append(items, buildFeedItem("exploitdb", "Exploit Database", "Public Exploits",
				"Public exploit code repository tracking verified proof-of-concept exploits.",
				u, mirror.ExploitDB.URL != "", true, stateMap["exploitdb"]))
		}
		if mirror.Metasploit != nil {
			u := mirror.Metasploit.URL
			if u == "" {
				u = defaultMetasploitURL
			}
			items = append(items, buildFeedItem("metasploit", "Metasploit Framework", "Weaponized Modules",
				"Rapid7 Metasploit Framework database of weaponized exploitation modules.",
				u, mirror.Metasploit.URL != "", true, stateMap["metasploit"]))
		}
		if mirror.EUVD != nil {
			u := mirror.EUVD.URL
			if u == "" {
				u = defaultEUVDURL
			}
			items = append(items, buildFeedItem("euvd", "EUVD (ENISA)", "European Intelligence",
				"European Union Vulnerability Database tracking vulnerabilities and European exploitation.",
				u, mirror.EUVD.URL != "", true, stateMap["euvd"]))
		}
		if mirror.VulnCheckKEV != nil {
			u := mirror.VulnCheckKEV.URL
			if u == "" {
				u = defaultVulnCheckURL
			}
			items = append(items, buildFeedItem("vulncheck_kev", "VulnCheck KEV", "Threat Intelligence",
				"VulnCheck Known Exploited Vulnerabilities catalog with commercial/community intelligence.",
				u, mirror.VulnCheckKEV.URL != "", true, stateMap["vulncheck_kev"]))
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
				targetURL, true, true, stateMap[c.Name]))
		}
	}

	return mirror, items, nil
}

func probeFeedURL(ctx context.Context, name, targetURL string) FeedTestResult {
	start := time.Now()
	res := FeedTestResult{
		Name: name,
		URL:  targetURL,
	}

	if targetURL == "" || strings.HasPrefix(targetURL, "/") {
		res.Reachable = true
		res.StatusCode = 200
		res.LatencyMs = 0
		res.Message = "Local API endpoint / Push feed ready"
		return res
	}

	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		res.Error = err.Error()
		res.Message = "Failed to construct request: " + err.Error()
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

func buildFeedItem(name, displayName, category, description, targetURL string, isMirror, enabled bool, st domain.FeedState) FeedItemResponse {
	status := "idle"
	if !enabled {
		status = "disabled"
	} else if st.Status != "" {
		status = st.Status
	}

	return FeedItemResponse{
		Name:        name,
		DisplayName: displayName,
		Category:    category,
		Description: description,
		URL:         targetURL,
		IsMirror:    isMirror,
		Enabled:     enabled,
		Status:      status,
		Records:     st.Records,
		LastSync:    st.LastSync,
		Error:       st.Error,
	}
}
