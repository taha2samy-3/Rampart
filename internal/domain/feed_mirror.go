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
	NVD  *NVDSource        `json:"nvd,omitempty"`
	OSV  *OSVSource        `json:"osv,omitempty"`
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
	// Enabled switches the feed off when false. Absent is on: KEV, EPSS, NVD and OSV run by default.
	Enabled *bool `json:"enabled,omitempty"`
}

// NVDSource configures the NVD feed. URL is a mirror and is optional: without it the public API is read (unless egress
// is deny). TokenFile is a file holding the NVD API key, sent as the apiKey header; it raises NIST's limit from 5 to
// 50 requests per 30 seconds. It is read at the start of every round, so a rotated key needs no restart.
type NVDSource struct {
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
	Schedule  string `json:"schedule,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"` // true switches NVD on, false off; absent is on only with a tokenFile
}

// On reports whether NVD runs. It is the one feed that needs an opt-in: without an API key its first sync is about 165 pages at one page every 6 seconds
// (NIST allows 5 requests per 30 seconds), which holds up everything after it, so NVD runs when `enabled: true` is written, or when `enabled` is absent
// and a tokenFile names the key. An absent block is off. (docs/34 item 21, F4.)
func (n *NVDSource) On() bool {
	if n == nil {
		return false
	}
	if n.Enabled != nil {
		return *n.Enabled
	}
	return n.TokenFile != ""
}

// OSVSource configures the OSV feed. Ecosystems names the OSV ecosystems to read (each is the archive
// <url>/<ecosystem>/all.zip; the list is the one OSV publishes in ecosystems.txt). OSV is large, so it runs only when
// ecosystems are named here, in the server configuration (feeds.osvEcosystems), or by storageMode full.
type OSVSource struct {
	URL        string   `json:"url,omitempty"`
	Ecosystems []string `json:"ecosystems,omitempty"`
	Schedule   string   `json:"schedule,omitempty"`
	Enabled    *bool    `json:"enabled,omitempty"` // false switches OSV off, whatever the ecosystems
}

// Where a token file may be. A token file is read by the server and sent to the feed's address, so a path to any file
// of the pod would let whoever writes a ClusterFeed send the session key or a database password to a host of their
// choice. Pull tokens live in their own Secret mount, apart from the server's own secrets (/etc/rampart/secrets).
const (
	FeedSecretsDir    = "/etc/rampart/feed-secrets" // tokenFile of a feed that is pulled
	FeedPushTokensDir = "/var/run/rampart/feeds"    // pushTokenFile of a feed plugin (D94)
)

// On reports whether an optional switch is on: absent is on, so a block that says nothing about it runs.
func On(enabled *bool) bool { return enabled == nil || *enabled }

// Off reports whether the block is switched off.
func (s *FeedSource) Off() bool { return s != nil && !On(s.Enabled) }

// Off reports whether the feed is switched off.
func (c CustomFeed) Off() bool { return !On(c.Enabled) }

// maxOSVEcosystems bounds the list: each is a download of up to gigabytes.
const maxOSVEcosystems = 64

var osvEcosystemRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,63}$`)

// publicFeedHosts are the addresses the feeds use by default. With egress deny none of them may be a feed's address:
// deny means "read only from your own mirror", and a mirror block that names the public host would still reach it.
var publicFeedHosts = map[string]bool{
	"services.nvd.nist.gov":                      true,
	"www.cisa.gov":                               true,
	"epss.cyentia.com":                           true,
	"osv-vulnerabilities.storage.googleapis.com": true,
	"gitlab.com":                                 true,
	"raw.githubusercontent.com":                  true,
	"github.com":                                 true,
	"euvdservices.enisa.europa.eu":               true,
	"api.vulncheck.com":                          true,
}

// Redacted returns a copy that is safe to show to any signed-in user: where a token is read from is a fact about the
// server's file system, so the path is replaced by "(set)".
func (s *FeedMirrorSpec) Redacted() *FeedMirrorSpec {
	if s == nil {
		return nil
	}
	cp := *s
	mask := func(p string) string {
		if p == "" {
			return ""
		}
		return "(set)"
	}
	if s.NVD != nil {
		n := *s.NVD
		n.URL, n.TokenFile = RedactFeedURL(n.URL), mask(n.TokenFile)
		cp.NVD = &n
	}
	if s.OSV != nil {
		o := *s.OSV
		o.URL = RedactFeedURL(o.URL)
		cp.OSV = &o
	}
	if s.EPSS != nil {
		e := *s.EPSS
		e.URL = RedactFeedURL(e.URL)
		cp.EPSS = &e
	}
	if s.KEV != nil {
		k := *s.KEV
		k.URL = RedactFeedURL(k.URL)
		cp.KEV = &k
	}
	for _, f := range []**FeedSource{&cp.Vulnrichment, &cp.ExploitDB, &cp.Metasploit, &cp.EUVD, &cp.VulnCheckKEV} {
		if *f != nil {
			c := **f
			c.URL, c.TokenFile = RedactFeedURL(c.URL), mask(c.TokenFile)
			*f = &c
		}
	}
	if s.Custom != nil {
		cp.Custom = make([]CustomFeed, len(s.Custom))
		for i, c := range s.Custom {
			c.URL, c.TokenFile, c.PushTokenFile = RedactFeedURL(c.URL), mask(c.TokenFile), mask(c.PushTokenFile)
			cp.Custom[i] = c
		}
	}
	return &cp
}

// RedactFeedURL drops the user name, the password and the query of a feed address before it is shown or logged: a
// signed address carries its credential in the query.
func RedactFeedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// FeedSource switches an optional source on. URL, when set, replaces the public address (a mirror). TokenFile is a
// path to a file holding the API token (a mounted Secret): the token never enters the resource or the database.
type FeedSource struct {
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
	// Enabled false is the same as leaving the block out: the source is not read and its rows are removed.
	Enabled *bool `json:"enabled,omitempty"`
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
	// Enabled false switches the feed off: it is not read and its rows are removed.
	Enabled *bool `json:"enabled,omitempty"`
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
		if err := checkTokenFile(name, src.TokenFile, FeedSecretsDir); err != nil {
			return nil, err
		}
	}
	if s.VulnCheckKEV != nil && On(s.VulnCheckKEV.Enabled) && s.VulnCheckKEV.TokenFile == "" {
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
			if err := checkTokenFile("custom "+c.Name+" push", c.PushTokenFile, FeedPushTokensDir); err != nil {
				return nil, err
			}
		case !httpURL(c.URL):
			return nil, fmt.Errorf("clusterfeedmirror: custom %s.url must be an http(s) URL, got %q", c.Name, c.URL)
		}
		if c.Format != CustomFeedOSVZip && c.Format != CustomFeedIntelJSONL {
			return nil, fmt.Errorf("clusterfeedmirror: custom %s.format must be %s or %s, got %q", c.Name, CustomFeedOSVZip, CustomFeedIntelJSONL, c.Format)
		}
		if err := checkTokenFile("custom "+c.Name, c.TokenFile, FeedSecretsDir); err != nil {
			return nil, err
		}
	}
	for name, src := range map[string]*FeedMirrorSource{"epss": s.EPSS, "kev": s.KEV} {
		if src == nil {
			continue
		}
		if src.Schedule != "" {
			return nil, fmt.Errorf("clusterfeedmirror: %s.schedule is not built; every feed runs every feeds.interval", name)
		}
		if !httpURL(src.URL) {
			return nil, fmt.Errorf("clusterfeedmirror: %s.url must be an http(s) URL, got %q", name, src.URL)
		}
	}
	// nvd and osv: the address is optional (the block can be only a token, or only the ecosystems to read).
	if s.NVD != nil {
		if s.NVD.Schedule != "" {
			return nil, fmt.Errorf("clusterfeedmirror: nvd.schedule is not built; every feed runs every feeds.interval")
		}
		if s.NVD.URL != "" && !httpURL(s.NVD.URL) {
			return nil, fmt.Errorf("clusterfeedmirror: nvd.url must be an http(s) URL, got %q", s.NVD.URL)
		}
		if err := checkTokenFile("nvd", s.NVD.TokenFile, FeedSecretsDir); err != nil {
			return nil, err
		}
	}
	if s.OSV != nil {
		if s.OSV.Schedule != "" {
			return nil, fmt.Errorf("clusterfeedmirror: osv.schedule is not built; every feed runs every feeds.interval")
		}
		if s.OSV.URL != "" && !httpURL(s.OSV.URL) {
			return nil, fmt.Errorf("clusterfeedmirror: osv.url must be an http(s) URL, got %q", s.OSV.URL)
		}
		if len(s.OSV.Ecosystems) > maxOSVEcosystems {
			return nil, fmt.Errorf("clusterfeedmirror: osv.ecosystems lists %d ecosystems; at most %d", len(s.OSV.Ecosystems), maxOSVEcosystems)
		}
		seenEco := map[string]bool{}
		for _, e := range s.OSV.Ecosystems {
			if !osvEcosystemRE.MatchString(e) || seenEco[e] {
				return nil, fmt.Errorf("clusterfeedmirror: osv.ecosystems: %q is not a distinct OSV ecosystem name (letters, digits, space and . _ : + -)", e)
			}
			seenEco[e] = true
		}
	}
	if s.Egress == "deny" {
		if err := s.refusePublicAddresses(); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// refusePublicAddresses is the rule of egress deny: no feed's address is one of the public hosts the feeds use by
// default. The error names the source, so the fix is to put the mirror's address there (or to leave the block out).
func (s *FeedMirrorSpec) refusePublicAddresses() error {
	check := func(name, raw string) error {
		if raw == "" {
			return nil
		}
		if u, err := url.Parse(raw); err == nil && publicFeedHosts[strings.ToLower(u.Hostname())] {
			return fmt.Errorf("clusterfeedmirror: egress is deny, but %s.url is the public address %s; give the address of your mirror", name, u.Hostname())
		}
		return nil
	}
	var pairs []struct{ name, url string }
	if s.KEV != nil && On(s.KEV.Enabled) {
		pairs = append(pairs, struct{ name, url string }{"kev", s.KEV.URL})
	}
	if s.EPSS != nil && On(s.EPSS.Enabled) {
		pairs = append(pairs, struct{ name, url string }{"epss", s.EPSS.URL})
	}
	if s.NVD != nil && s.NVD.Enabled == nil || s.NVD != nil && *s.NVD.Enabled { // a block that is not switched off has its address checked, on or not
		pairs = append(pairs, struct{ name, url string }{"nvd", s.NVD.URL})
	}
	if s.OSV != nil && On(s.OSV.Enabled) {
		pairs = append(pairs, struct{ name, url string }{"osv", s.OSV.URL})
	}
	for _, f := range []struct {
		name string
		src  *FeedSource
	}{{"vulnrichment", s.Vulnrichment}, {"exploitdb", s.ExploitDB}, {"metasploit", s.Metasploit}, {"euvd", s.EUVD}, {"vulncheckKev", s.VulnCheckKEV}} {
		if f.src != nil && On(f.src.Enabled) {
			pairs = append(pairs, struct{ name, url string }{f.name, f.src.URL})
		}
	}
	for _, p := range pairs {
		if err := check(p.name, p.url); err != nil {
			return err
		}
	}
	return nil
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

// checkTokenFile accepts an absolute, clean path inside dir. The token itself is read by the sync at the start of each
// round; the sync checks the path again, with symbolic links resolved, because a Kubernetes Secret mount is a tree of
// links and only the resolved path says where the bytes are.
func checkTokenFile(name, p, dir string) error {
	if p == "" {
		return nil
	}
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("clusterfeedmirror: %s.tokenFile must be an absolute, clean path, got %q", name, p)
	}
	if !strings.HasPrefix(p, dir+"/") {
		return fmt.Errorf("clusterfeedmirror: %s.tokenFile must be a file under %s (a mounted Secret kept for feeds), got %q", name, dir, p)
	}
	return nil
}

// FeedTokenPathAllowed reports whether a token file lies inside dir once symbolic links are resolved. resolved is the
// path after EvalSymlinks.
func FeedTokenPathAllowed(resolved, dir string) bool {
	return strings.HasPrefix(path.Clean(resolved), path.Clean(dir)+"/")
}
