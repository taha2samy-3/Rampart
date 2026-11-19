package enrich

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"rampart/internal/telemetry"
)

// FeedResult is what one feed did in a sync round.
type FeedResult struct {
	Feed    string
	Records int64
	Err     error
	// NotModified: the server said the file had not changed since the last round, so nothing was read (conditional GET).
	NotModified bool
	// Duration is how long the feed's step took, from begin to the last word on it.
	Duration time.Duration
}

// begin marks the start of a feed's step in the round, so its duration can be measured when the step ends.
func (s *FeedSyncer) begin(feed string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.starts == nil {
		s.starts = map[string]time.Time{}
	}
	s.starts[feed] = time.Now()
	s.began++
}

// ranFeeds is how many feeds the last round began: 0 when every feed was fresh and nothing was done.
func (s *FeedSyncer) ranFeeds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.began
}

// due reports whether a feed is to be synced in a scheduled round (cfg.OnlyDue). A feed that never synced is due at once
// (a feed switched on in the ClusterFeed does not wait for the next interval); a feed whose last round failed is due again
// at every check, which is how a failure is retried; one that succeeded is due when its interval has passed; one that is
// syncing right now is not. Without OnlyDue, a manual sync or a one-feed round, every feed is due.
func (s *FeedSyncer) due(ctx context.Context, cfg FeedConfig, feed string) bool {
	if !cfg.OnlyDue {
		return true
	}
	st, err := s.GetFeedState(ctx, feed)
	if err != nil {
		return true
	}
	switch st.Status {
	case "success":
		return st.LastSync == nil || time.Since(*st.LastSync) >= cfg.Interval
	case "syncing", "queued":
		return false
	}
	return true // never synced, or the last round failed
}

// recordMetrics reports a finished round to the metrics: one sync per feed, with its status, duration and records.
// It runs once per round on the final results, so a failure recorded by two layers is counted once.
func recordMetrics(ctx context.Context, rs []FeedResult) {
	for _, r := range rs {
		status := "success"
		if r.Err != nil {
			status = "failure"
		}
		telemetry.RecordFeedSync(ctx, r.Feed, status)
		if r.Duration > 0 {
			telemetry.RecordFeedDuration(ctx, r.Feed, r.Duration)
		}
		if r.Err == nil && !r.NotModified {
			telemetry.RecordFeedRecords(ctx, r.Feed, r.Records)
		}
	}
}

// note records what a feed did; the last word on a feed wins (a failure can be recorded by two layers).
func (s *FeedSyncer) note(r FeedResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.starts[r.Feed]; ok {
		r.Duration = time.Since(t)
	}
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
		if r.NotModified {
			lines = append(lines, fmt.Sprintf("%s: unchanged (%d records)", labelOf(r.Feed), r.Records))
			continue
		}
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

// recordFreshness reports, for every feed that has synced successfully, when it last did, read from the database so that
// a sync made by another replica, or before a restart, counts. It is what the "feed has not synced" alert reads.
func (s *FeedSyncer) recordFreshness(ctx context.Context) {
	rows, err := s.pool.Query(ctx, `SELECT feed, last_sync FROM feed_state WHERE status = 'success' AND last_sync IS NOT NULL`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var feed string
		var at time.Time
		if rows.Scan(&feed, &at) == nil {
			telemetry.RecordFeedLastSuccess(ctx, feed, at)
		}
	}
}
