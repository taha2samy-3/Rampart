package enrich

import (
	"fmt"
	"sort"
	"strings"
)

// FeedResult is what one feed did in a sync round.
type FeedResult struct {
	Feed    string
	Records int64
	Err     error
}

// note records what a feed did; the last word on a feed wins (a failure can be recorded by two layers).
func (s *FeedSyncer) note(r FeedResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.results {
		if s.results[i].Feed == r.Feed {
			s.results[i] = r
			return
		}
	}
	s.results = append(s.results, r)
}

// feedLabels are the names people know the feeds by.
var feedLabels = map[string]string{
	"cisa_kev": "CISA KEV", "first_epss": "FIRST EPSS", "nvd": "NVD", "osv": "OSV", "vulnrichment": "CISA Vulnrichment",
	"exploitdb": "Exploit Database", "metasploit": "Metasploit", "euvd": "EUVD", "vulncheck_kev": "VulnCheck KEV",
}

func labelOf(feed string) string {
	if l, ok := feedLabels[feed]; ok {
		return l
	}
	return feed
}

// Summarize turns a round into one message: a title, a body with a line per feed, and whether any feed failed. One
// message per round, not one per feed, so a scheduled round is one notification.
func Summarize(rs []FeedResult) (title, body string, failed bool) {
	rs = append([]FeedResult(nil), rs...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Feed < rs[j].Feed })
	var ok, bad []string
	var lines []string
	for _, r := range rs {
		if r.Err != nil {
			bad = append(bad, labelOf(r.Feed))
			lines = append(lines, fmt.Sprintf("%s: failed: %s", labelOf(r.Feed), r.Err))
			continue
		}
		ok = append(ok, labelOf(r.Feed))
		lines = append(lines, fmt.Sprintf("%s: %d records", labelOf(r.Feed), r.Records))
	}
	switch {
	case len(bad) == 0:
		title = "Vulnerability feeds synced: " + strings.Join(ok, ", ")
	case len(ok) == 0:
		title = "Vulnerability feed sync failed: " + strings.Join(bad, ", ")
	default:
		title = fmt.Sprintf("Vulnerability feeds synced; %s failed", strings.Join(bad, ", "))
	}
	return title, strings.Join(lines, "\n"), len(bad) > 0
}
