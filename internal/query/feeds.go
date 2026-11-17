package query

import (
	"net/http"
	"strings"
	"time"

	"rampart/internal/domain"
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

	mirror, err := a.store.GetClusterFeedMirror(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to get cluster feed mirror")
		return
	}

	states, err := a.store.ListFeedStates(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list feed states")
		return
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

	writeJSON(w, http.StatusOK, FeedsListResponse{
		Mirror: mirror,
		Items:  items,
	})
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
