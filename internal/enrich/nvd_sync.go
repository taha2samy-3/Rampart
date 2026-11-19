package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// NVD sync (docs/01 D3, D14; D86). The NVD CVE API 2.0 is paged (at most 2,000 records a page) and rate-limited:
// 5 requests in a rolling 30 seconds without an API key, 50 with one, and NIST asks clients to sleep between
// requests. The first sync reads every CVE; later syncs ask only for what changed since the last success
// (lastModStartDate/lastModEndDate, at most 120 days apart; a longer gap falls back to a full read).
//
// What it writes, into the global vulnerability table (D19, as the system role): the English description when
// none is stored, the CWEs, every CVSS metric as {version, vector, score, source}, and the best score and vector
// (4.0, else 3.1, else 3.0). KEV and EPSS columns are never touched. Detection is not NVD's job: findings still
// come from the scanners and Dependency-Track (D39).

const (
	DefaultNVDURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize     = 2000
	nvdMaxRangeDays = 120
	maxNVDPageBytes = 64 << 20
	nvdDelayNoKey   = 6 * time.Second        // 5 requests per 30 s
	nvdDelayWithKey = 700 * time.Millisecond // 50 requests per 30 s
)

type nvdPage struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V40 []nvdMetric `json:"cvssMetricV40"`
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"` // Primary | Secondary
	CvssData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type cvssEntry struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Source  string  `json:"source"`
}

// syncNVD reads the NVD from the cursor (the last successful sync) to now and writes each page in one batch.
func (s *FeedSyncer) syncNVD(ctx context.Context, cfg FeedConfig) (int, error) {
	since, _ := s.lastSuccess(ctx, "nvd")
	now := time.Now().UTC()
	full := since.IsZero() || now.Sub(since) > nvdMaxRangeDays*24*time.Hour
	delay := cfg.NVDPageDelay
	if delay == 0 {
		delay = nvdDelayNoKey
		if cfg.NVDAPIKey != "" {
			delay = nvdDelayWithKey
		}
	}
	total, start := 0, 0
	for {
		q := url.Values{}
		q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
		q.Set("startIndex", strconv.Itoa(start))
		if !full {
			q.Set("lastModStartDate", since.Add(-time.Hour).Format("2006-01-02T15:04:05.000Z"))
			q.Set("lastModEndDate", now.Format("2006-01-02T15:04:05.000Z"))
		}
		page, err := s.fetchNVDPage(ctx, cfg, cfg.NVDURL+"?"+q.Encode())
		if err != nil {
			return total, err
		}
		n, err := s.writeNVDPage(ctx, page)
		total += n
		if err != nil {
			return total, err
		}
		start += page.ResultsPerPage
		if page.ResultsPerPage == 0 || start >= page.TotalResults {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// nvdMaxAttempts is how many times one page is asked for when NIST answers that the client is too fast.
const nvdMaxAttempts = 4

// fetchNVDPage asks for one page. NIST answers 429 when the client is over its limit (and, with 403, when it was
// told to slow down), and 503 when it is busy; each is waited out for the time the server names in Retry-After, or
// 30 seconds, the length of NIST's window, doubled each time, and then asked again. A page that fails otherwise, or
// after the last attempt, fails the sync, and the cursor stays where it was.
func (s *FeedSyncer) fetchNVDPage(ctx context.Context, cfg FeedConfig, u string) (*nvdPage, error) {
	base := cfg.NVDRetryBase
	if base <= 0 {
		base = 30 * time.Second
	}
	var lastStatus int
	for attempt := 0; attempt < nvdMaxAttempts; attempt++ {
		page, status, wait, err := s.fetchNVDPageOnce(ctx, cfg, u, base<<attempt)
		if err != nil {
			return nil, err
		}
		if page != nil {
			return page, nil
		}
		lastStatus = status
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("GET %s: NVD still answered %d after %d attempts (rate limit); the next round asks again from the same point", redact(cfg.NVDURL), lastStatus, nvdMaxAttempts)
}

// fetchNVDPageOnce makes one request. It returns the page, or, for an answer worth waiting out (429, 403, 503), the
// status and how long to wait; any other failure is an error.
func (s *FeedSyncer) fetchNVDPageOnce(ctx context.Context, cfg FeedConfig, u string, defaultWait time.Duration) (page *nvdPage, status int, wait time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", "rampart-feed-sync")
	if cfg.NVDAPIKey != "" {
		req.Header.Set("apiKey", cfg.NVDAPIKey)
	}
	res, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = res.Body.Close() }()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		return nil, res.StatusCode, retryAfter(res.Header.Get("Retry-After"), defaultWait), nil
	default:
		return nil, res.StatusCode, 0, fmt.Errorf("GET %s: status %d", redact(cfg.NVDURL), res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxNVDPageBytes+1))
	if err != nil {
		return nil, 0, 0, err
	}
	if int64(len(body)) > maxNVDPageBytes {
		return nil, 0, 0, fmt.Errorf("nvd page larger than the %d byte limit; refused, not cut", maxNVDPageBytes)
	}
	var p nvdPage
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, 0, 0, fmt.Errorf("nvd page: %w", err)
	}
	return &p, http.StatusOK, 0, nil
}

// maxRetryAfter caps what a server can make the sync wait for in one step.
const maxRetryAfter = 5 * time.Minute

// retryAfter reads a Retry-After header: seconds, or an HTTP date. An absent or unreadable one gives def. The wait
// is never longer than maxRetryAfter.
func retryAfter(h string, def time.Duration) time.Duration {
	h = strings.TrimSpace(h)
	d := def
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		d = 0
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

func (s *FeedSyncer) writeNVDPage(ctx context.Context, page *nvdPage) (int, error) {
	batch := &pgx.Batch{}
	for _, v := range page.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		var cwes []int
		for _, w := range v.CVE.Weaknesses {
			for _, d := range w.Description {
				if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(d.Value), "CWE-")); err == nil && strings.HasPrefix(strings.ToUpper(d.Value), "CWE-") {
					cwes = appendUniqueInt(cwes, n)
				}
			}
		}
		// Every metric is kept. The best one is NVD's primary score in the newest version (4.0, then 3.1, then 3.0);
		// only when no version has a primary score does a secondary one (a CNA's) stand in.
		var all []cvssEntry
		var best *cvssEntry
		sets := [][]nvdMetric{v.CVE.Metrics.V40, v.CVE.Metrics.V31, v.CVE.Metrics.V30}
		for _, set := range sets {
			for _, m := range set {
				all = append(all, cvssEntry{Version: m.CvssData.Version, Vector: m.CvssData.VectorString, Score: m.CvssData.BaseScore, Source: "nvd:" + m.Source})
			}
		}
		for _, wantPrimary := range []bool{true, false} {
			for _, set := range sets {
				for _, m := range set {
					if best == nil && (m.Type == "Primary") == wantPrimary {
						best = &cvssEntry{Version: m.CvssData.Version, Vector: m.CvssData.VectorString, Score: m.CvssData.BaseScore}
					}
				}
			}
		}
		cvssJSON, _ := json.Marshal(all)
		if all == nil {
			cvssJSON = []byte("[]")
		}
		var bestScore *float64
		var bestVector *string
		if best != nil {
			bestScore, bestVector = &best.Score, &best.Vector
		}
		if cwes == nil {
			cwes = []int{}
		}
		var published, modified *time.Time
		if t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.Published); err == nil {
			published = &t
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.LastModified); err == nil {
			modified = &t
		}
		batch.Queue(`
			INSERT INTO vulnerability (id, description, cwes, cvss, cvss_best_score, cvss_best_vector, published, modified, updated_at)
			VALUES ($1, NULLIF($2, ''), $3, $4::jsonb, $5, $6, $7, $8, NOW())
			ON CONFLICT (id) DO UPDATE SET
				description      = COALESCE(vulnerability.description, EXCLUDED.description),
				cwes             = EXCLUDED.cwes,
				cvss             = EXCLUDED.cvss,
				cvss_best_score  = EXCLUDED.cvss_best_score,
				cvss_best_vector = EXCLUDED.cvss_best_vector,
				published        = COALESCE(EXCLUDED.published, vulnerability.published),
				modified         = EXCLUDED.modified,
				updated_at       = NOW()`,
			id, desc, cwes, cvssJSON, bestScore, bestVector, published, modified)
	}
	if batch.Len() == 0 {
		return 0, nil
	}
	br := s.pool.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return i, fmt.Errorf("enrich: writing NVD batch: %w", err)
		}
	}
	return batch.Len(), nil
}

func appendUniqueInt(xs []int, n int) []int {
	for _, x := range xs {
		if x == n {
			return xs
		}
	}
	return append(xs, n)
}

// lastSuccess reads the NVD cursor: the start time of the last sync that completed. A failed sync leaves it, so
// the next one asks again from the same point.
func (s *FeedSyncer) lastSuccess(ctx context.Context, feed string) (time.Time, error) {
	st, err := s.GetFeedState(ctx, feed)
	if err != nil || st == nil || st.Cursor == nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, *st.Cursor)
}

// recordNVDSuccess stores the records written and the cursor for the next incremental sync.
func (s *FeedSyncer) recordNVDSuccess(ctx context.Context, startedAt time.Time, records int64) error {
	s.note(FeedResult{Feed: "nvd", Records: records})
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_state (feed, cursor, last_sync, records, status, error)
		VALUES ('nvd', $1, NOW(), $2, 'success', NULL)
		ON CONFLICT (feed) DO UPDATE SET cursor = EXCLUDED.cursor, last_sync = EXCLUDED.last_sync,
			records = EXCLUDED.records, status = 'success', error = NULL`,
		startedAt.UTC().Format(time.RFC3339), records)
	return err
}
