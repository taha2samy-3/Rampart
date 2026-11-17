package domain

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// FeedMirrorSpec is a ClusterFeedMirror (docs/04, D86, D88): where the vulnerability-intelligence feeds are read
// from, which of the optional ones run, and whether any other address may be called. It is configuration, written by
// the operator or `rampart apply` from a resource in Git; the feed code stays in the core, because feeds write the
// global tables every tenant reads (D19) and a plugin must never be able to.
//
// KEV, EPSS and NVD run by default (the built-in risk policy reads them); for them a block is a mirror. The other
// sources (D88) run only when listed; for them the block switches the source on, and url, when set, is its mirror.
type FeedMirrorSpec struct {
	NVD  *FeedMirrorSource `json:"nvd,omitempty"`
	OSV  *FeedMirrorSource `json:"osv,omitempty"`
	EPSS *FeedMirrorSource `json:"epss,omitempty"`
	KEV  *FeedMirrorSource `json:"kev,omitempty"`
	CWE  *FeedMirrorSource `json:"cwe,omitempty"`
	// Optional sources (D88).
	Vulnrichment *FeedSource  `json:"vulnrichment,omitempty"` // CISA ADP: SSVC, and CVSS/CWE NVD has not added (CC0)
	ExploitDB    *FeedSource  `json:"exploitdb,omitempty"`    // public exploit code: maturity poc
	Metasploit   *FeedSource  `json:"metasploit,omitempty"`   // exploit modules: maturity weaponized
	EUVD         *FeedSource  `json:"euvd,omitempty"`         // ENISA: EUVD ids and EU-reported exploitation
	VulnCheckKEV *FeedSource  `json:"vulncheckKev,omitempty"` // VulnCheck KEV: token required (community or commercial)
	Custom       []CustomFeed `json:"custom,omitempty"`       // licensed or in-house intelligence, in a documented format
	Egress       string       `json:"egress,omitempty"`       // allow (default) | deny: no feed is read from anywhere but its mirror
	// StorageMode controls whether vulnerability intelligence is cached incrementally (lightweight, default)
	// or stored as a full offline local database (full / standalone, like Dependency-Track).
	StorageMode string `json:"storageMode,omitempty"`
}

// FeedMirrorSource is one feed's mirror.
type FeedMirrorSource struct {
	URL      string `json:"url"`
	Schedule string `json:"schedule,omitempty"`
}

// FeedSource switches an optional source on. URL, when set, replaces the public address (a mirror). TokenFile is a
// path to a file holding the API token (a mounted Secret): the token never enters the resource or the database.
type FeedSource struct {
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
}

// Custom feed formats (D88). A licensed feed (VulnDB, Recorded Future, Mandiant, Flashpoint, Snyk …) is brought in by
// exporting or proxying it into one of these; Rampart does not ship clients for APIs it cannot test or whose terms
// it has not accepted.
const (
	CustomFeedOSVZip     = "osv-zip"     // a zip of OSV JSON records (the format OSV.dev and GitHub publish)
	CustomFeedIntelJSONL = "intel-jsonl" // one exploitation record per line (docs/16 D88)
)

// CustomFeed is one licensed or in-house source.
type CustomFeed struct {
	Name      string `json:"name"` // source label shown in the score's reason; lowercase, [a-z0-9-]
	URL       string `json:"url,omitempty"`
	Format    string `json:"format"`
	TokenFile string `json:"tokenFile,omitempty"` // sent as Authorization: Bearer
	// PushTokenFile makes the feed a push feed (D89, D94): a feed plugin posts the file to POST /api/v1/feeds/{name}
	// with this token as its bearer token, instead of Rampart pulling a URL. The query-api pods mount the file.
	PushTokenFile string `json:"pushTokenFile,omitempty"`
}

// ParseFeedMirrorSpec validates a ClusterFeedMirror. What this version does not do is refused with the reason, not
// accepted and ignored (the rule of D41): a per-feed schedule (feeds run together every feeds.interval) and the CWE
// feed (not synced).
func ParseFeedMirrorSpec(raw []byte) (*FeedMirrorSpec, error) {
	var s FeedMirrorSpec
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("clusterfeedmirror: %w", err)
	}
	switch s.Egress {
	case "", "allow", "deny":
	default:
		return nil, fmt.Errorf("clusterfeed: egress must be allow or deny, got %q", s.Egress)
	}
	switch s.StorageMode {
	case "", "lightweight", "full", "standalone":
	default:
		return nil, fmt.Errorf("clusterfeed: storageMode must be lightweight, full, or standalone, got %q", s.StorageMode)
	}
	if s.CWE != nil {
		return nil, fmt.Errorf("clusterfeedmirror: the cwe feed is not synced by this version; remove it")
	}
	for name, src := range map[string]*FeedSource{"vulnrichment": s.Vulnrichment, "exploitdb": s.ExploitDB, "metasploit": s.Metasploit, "euvd": s.EUVD, "vulncheckKev": s.VulnCheckKEV} {
		if src == nil {
			continue
		}
		if src.URL != "" && !httpURL(src.URL) {
			return nil, fmt.Errorf("clusterfeedmirror: %s.url must be an http(s) URL, got %q", name, src.URL)
		}
		if err := checkTokenFile(name, src.TokenFile); err != nil {
			return nil, err
		}
	}
	if s.VulnCheckKEV != nil && s.VulnCheckKEV.TokenFile == "" {
		return nil, fmt.Errorf("clusterfeedmirror: vulncheckKev needs tokenFile; VulnCheck answers no request without a token")
	}
	seen := map[string]bool{}
	for i, c := range s.Custom {
		if !feedNameRE.MatchString(c.Name) || builtinFeedNames[c.Name] || seen[c.Name] {
			return nil, fmt.Errorf("clusterfeedmirror: custom[%d].name %q must be unique, lowercase [a-z0-9-], and not a built-in feed's name", i, c.Name)
		}
		seen[c.Name] = true
		switch {
		case c.PushTokenFile != "" && c.URL != "":
			return nil, fmt.Errorf("clusterfeedmirror: custom %s: url (pull) or pushTokenFile (push), not both", c.Name)
		case c.PushTokenFile != "":
			if c.Format != CustomFeedIntelJSONL {
				return nil, fmt.Errorf("clusterfeedmirror: custom %s: a push feed is intel-jsonl; an OSV zip is pulled from a url", c.Name)
			}
			if err := checkTokenFile("custom "+c.Name+" push", c.PushTokenFile); err != nil {
				return nil, err
			}
		case !httpURL(c.URL):
			return nil, fmt.Errorf("clusterfeedmirror: custom %s.url must be an http(s) URL, got %q", c.Name, c.URL)
		}
		if c.Format != CustomFeedOSVZip && c.Format != CustomFeedIntelJSONL {
			return nil, fmt.Errorf("clusterfeedmirror: custom %s.format must be %s or %s, got %q", c.Name, CustomFeedOSVZip, CustomFeedIntelJSONL, c.Format)
		}
		if err := checkTokenFile("custom "+c.Name, c.TokenFile); err != nil {
			return nil, err
		}
	}
	for name, src := range map[string]*FeedMirrorSource{"nvd": s.NVD, "osv": s.OSV, "epss": s.EPSS, "kev": s.KEV} {
		if src == nil {
			continue
		}
		if src.Schedule != "" {
			return nil, fmt.Errorf("clusterfeedmirror: %s.schedule is not built; every feed runs every feeds.interval", name)
		}
		u, err := url.Parse(src.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("clusterfeedmirror: %s.url must be an http(s) URL, got %q", name, src.URL)
		}
	}
	return &s, nil
}

var feedNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// builtinFeedNames are the source labels the built-in feeds use; a custom feed cannot take one, so a licensed feed
// can never pass for CISA's or NIST's data.
var builtinFeedNames = map[string]bool{
	"cisa_kev": true, "first_epss": true, "nvd": true, "osv": true, "vulnrichment": true, "exploitdb": true,
	"metasploit": true, "euvd": true, "vulncheck_kev": true, "vulncheck-kev": true, "cisa-kev": true,
}

func httpURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// checkTokenFile accepts an absolute, clean path. The token itself is read by the sync at the start of each round.
func checkTokenFile(name, p string) error {
	if p == "" {
		return nil
	}
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("clusterfeedmirror: %s.tokenFile must be an absolute, clean path (a mounted Secret), got %q", name, p)
	}
	return nil
}
