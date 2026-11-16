package domain

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// FeedMirrorSpec is a ClusterFeedMirror (docs/04, D86): where the vulnerability-intelligence feeds are read from,
// and whether any other address may be called. It is configuration, written by the operator or `rampart apply`
// from a resource in Git; the feed code stays in the core, because feeds write the global tables every tenant
// reads (D19) and a plugin must never be able to.
type FeedMirrorSpec struct {
	NVD    *FeedMirrorSource `json:"nvd,omitempty"`
	OSV    *FeedMirrorSource `json:"osv,omitempty"`
	EPSS   *FeedMirrorSource `json:"epss,omitempty"`
	KEV    *FeedMirrorSource `json:"kev,omitempty"`
	CWE    *FeedMirrorSource `json:"cwe,omitempty"`
	Egress string            `json:"egress,omitempty"` // allow (default) | deny: no feed is read from anywhere but its mirror
}

// FeedMirrorSource is one feed's mirror.
type FeedMirrorSource struct {
	URL      string `json:"url"`
	Schedule string `json:"schedule,omitempty"`
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
		return nil, fmt.Errorf("clusterfeedmirror: egress must be allow or deny, got %q", s.Egress)
	}
	if s.CWE != nil {
		return nil, fmt.Errorf("clusterfeedmirror: the cwe feed is not synced by this version; remove it")
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
