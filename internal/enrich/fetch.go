package enrich

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Default upstream locations. Each can be pointed at an internal mirror (air-gapped installs, doc 15).
const (
	DefaultKEVURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL    = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	DefaultOSVBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
)

// Download size caps. A feed bigger than this is refused rather than filling the disk or memory.
const (
	maxKEVBytes  = 64 << 20
	maxEPSSBytes = 512 << 20
	maxOSVBytes  = 2 << 30
)

// FeedConfig says which feeds run and where they come from.
type FeedConfig struct {
	KEVURL        string
	EPSSURL       string
	OSVBaseURL    string
	OSVEcosystems []string // empty: OSV is not synced (it is large, so it is opt-in)
	Interval      time.Duration
	HTTPClient    *http.Client
	TempDir       string
}

func (c *FeedConfig) defaults() {
	if c.KEVURL == "" {
		c.KEVURL = DefaultKEVURL
	}
	if c.EPSSURL == "" {
		c.EPSSURL = DefaultEPSSURL
	}
	if c.OSVBaseURL == "" {
		c.OSVBaseURL = DefaultOSVBaseURL
	}
	if c.Interval <= 0 {
		c.Interval = 6 * time.Hour
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Minute}
	}
}

// get downloads url, refusing bodies over max bytes, and returns the body.
func (c *FeedConfig) get(ctx context.Context, url string, max int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rampart-feed-sync")
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", url, res.StatusCode)
	}
	if res.ContentLength > max {
		_ = res.Body.Close()
		return nil, fmt.Errorf("GET %s: %d bytes exceeds the %d byte limit", url, res.ContentLength, max)
	}
	return &limitedBody{Reader: io.LimitReader(res.Body, max+1), c: res.Body, max: max}, nil
}

// limitedBody fails, rather than silently truncates, a body larger than its limit.
type limitedBody struct {
	io.Reader
	c   io.Closer
	n   int64
	max int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	l.n += int64(n)
	if l.n > l.max {
		return n, errors.New("the download is larger than the size limit")
	}
	return n, err
}
func (l *limitedBody) Close() error { return l.c.Close() }

// SyncAll downloads and applies every configured feed. One feed failing does not stop the others;
// the errors are joined.
func (s *FeedSyncer) SyncAll(ctx context.Context, cfg FeedConfig, log *slog.Logger) error {
	cfg.defaults()
	var errs []error

	if body, err := cfg.get(ctx, cfg.KEVURL, maxKEVBytes); err != nil {
		s.recordFeedError(ctx, "cisa_kev", err)
		errs = append(errs, fmt.Errorf("kev: %w", err))
	} else {
		n, err := s.SyncKEV(ctx, body)
		_ = body.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("kev: %w", err))
		} else {
			log.Info("feed synced", "feed", "cisa_kev", "records", n)
		}
	}

	if body, err := cfg.get(ctx, cfg.EPSSURL, maxEPSSBytes); err != nil {
		s.recordFeedError(ctx, "first_epss", err)
		errs = append(errs, fmt.Errorf("epss: %w", err))
	} else {
		var r io.Reader = body
		if strings.HasSuffix(strings.ToLower(cfg.EPSSURL), ".gz") {
			gz, gerr := gzip.NewReader(body)
			if gerr != nil {
				err = gerr
			} else {
				r = gz
			}
		}
		var n int
		if err == nil {
			n, err = s.SyncEPSS(ctx, r)
		}
		_ = body.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("epss: %w", err))
		} else {
			log.Info("feed synced", "feed", "first_epss", "records", n)
		}
	}

	if len(cfg.OSVEcosystems) > 0 {
		total := 0
		var osvErr error
		for _, eco := range cfg.OSVEcosystems {
			n, err := s.syncOSVEcosystem(ctx, cfg, eco)
			total += n
			if err != nil {
				osvErr = fmt.Errorf("osv %s: %w", eco, err)
				errs = append(errs, osvErr)
				break
			}
		}
		if osvErr != nil {
			s.recordFeedError(ctx, "osv", osvErr)
		} else if err := s.recordFeedSuccess(ctx, "osv", int64(total)); err != nil {
			errs = append(errs, err)
		} else {
			log.Info("feed synced", "feed", "osv", "records", total)
		}
	}
	return errors.Join(errs...)
}

// syncOSVEcosystem downloads <base>/<ecosystem>/all.zip to a temporary file (a zip needs random access),
// then streams its JSON files into the database a thousand records at a time.
func (s *FeedSyncer) syncOSVEcosystem(ctx context.Context, cfg FeedConfig, eco string) (int, error) {
	body, err := cfg.get(ctx, strings.TrimRight(cfg.OSVBaseURL, "/")+"/"+eco+"/all.zip", maxOSVBytes)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()
	tmp, err := os.CreateTemp(cfg.TempDir, "osv-*.zip")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	if _, err := io.Copy(tmp, body); err != nil {
		return 0, err
	}
	return s.SyncOSVZip(ctx, tmp.Name())
}

// SyncOSVZip applies every .json file of an OSV ecosystem archive.
func (s *FeedSyncer) SyncOSVZip(ctx context.Context, path string) (int, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = zr.Close() }()
	const chunkSize = 1000
	chunk := make([]OSVRecord, 0, chunkSize)
	count := 0
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		if err := s.writeOSVChunk(ctx, chunk); err != nil {
			return err
		}
		count += len(chunk)
		chunk = chunk[:0]
		return nil
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 32<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		var rec OSVRecord
		err = json.NewDecoder(io.LimitReader(rc, 32<<20)).Decode(&rec)
		_ = rc.Close()
		if err != nil || rec.ID == "" {
			continue // one malformed advisory must not stop the ecosystem
		}
		chunk = append(chunk, rec)
		if len(chunk) == chunkSize {
			if err := flush(); err != nil {
				return count, err
			}
		}
	}
	return count, flush()
}

// Lookup returns the intelligence for the given vulnerability ids as a small FeedStore, which
// risk.EvaluateRisk reads. The query API calls it for the ids on one page, so nothing is held in memory.
func (s *FeedSyncer) Lookup(ctx context.Context, ids []string) (*FeedStore, error) {
	fs := NewFeedStore()
	if len(ids) == 0 {
		return fs, nil
	}
	// Each requested id maps to its own row and to the rows its aliases point at, so a finding that
	// carries a GHSA id still gets the KEV and EPSS data of the CVE it is an alias of.
	req := make([]string, 0, 2*len(ids))
	for _, id := range ids {
		req = append(req, strings.TrimSpace(id), strings.ToUpper(strings.TrimSpace(id)))
	}
	rows, err := s.pool.Query(ctx, `
		WITH req AS (SELECT DISTINCT unnest($1::text[]) AS rid),
		m AS (
			SELECT rid, rid AS vid FROM req
			UNION
			SELECT r.rid, a.vulnerability_id FROM req r JOIN vulnerability_alias a ON a.alias = r.rid
		)
		SELECT m.rid, v.kev_date_added IS NOT NULL, v.kev_due_date, COALESCE(v.kev_ransomware, false),
		       v.epss_score, v.epss_percentile
		FROM m JOIN vulnerability v ON v.id = m.vid
		WHERE v.kev_date_added IS NOT NULL OR v.epss_score IS NOT NULL`, req)
	if err != nil {
		return nil, fmt.Errorf("enrich: looking up intelligence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id         string
			isKEV, ran bool
			due        *time.Time
			epss, pct  *float32
		)
		if err := rows.Scan(&id, &isKEV, &due, &ran, &epss, &pct); err != nil {
			return nil, err
		}
		if isKEV {
			fs.SetKEV(KEVEntry{CVEID: id, DueDate: due, KnownRansomwareCampaignUse: ran})
		}
		if epss != nil {
			score := EPSSScore{CVEID: id, EPSS: float64(*epss)}
			if pct != nil {
				score.Percentile = float64(*pct)
			}
			fs.SetEPSS(score)
		}
	}
	return fs, rows.Err()
}

// RunScheduler syncs the feeds at start and then every cfg.Interval. Only one replica syncs at a time:
// the others skip the round when they cannot take the advisory lock.
func RunScheduler(ctx context.Context, pool *pgxpool.Pool, cfg FeedConfig, log *slog.Logger) {
	cfg.defaults()
	syncer := NewFeedSyncer(pool)
	lockKey := int64(fnvKey("rampart/feed-sync"))
	round := func() {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			log.Warn("feed sync: no database connection", "error", err)
			return
		}
		defer conn.Release()
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
			return // another replica is syncing
		}
		defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()
		if err := syncer.SyncAll(ctx, cfg, log); err != nil {
			log.Warn("feed sync finished with errors", "error", err)
		}
	}
	// Do not hit the upstream on every restart: skip the start-up round when KEV synced recently.
	if st, err := syncer.GetFeedState(ctx, "cisa_kev"); err != nil || st.LastSync == nil || time.Since(*st.LastSync) > cfg.Interval || st.Status != "success" {
		round()
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			round()
		}
	}
}

func fnvKey(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64() >> 1)
}
