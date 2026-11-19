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
	"net/url"
	"os"
	"rampart/internal/domain"
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
	// OnRound is called when a SyncAll round ends, with what each feed did (success or error), for the scheduled
	// round and the one asked for on the feeds page alike: it tells the tenants and records a Kubernetes Event.
	OnRound func(ctx context.Context, results []FeedResult)

	// Only, when set, limits one SyncAll round to that feed (an on-demand sync of one row of the feeds page).
	Only string

	KEVURL        string
	EPSSURL       string
	OSVBaseURL    string
	OSVEcosystems []string // empty: OSV is not synced (it is large, so it is opt-in)
	// NVD (D86): on by default. The API key raises NIST's limit from 5 to 50 requests per 30 seconds.
	NVDURL       string
	NVDAPIKey    string
	NVDDisabled  bool
	NVDPageDelay time.Duration // tests only; zero picks the delay NIST asks for
	// SourcePageDelay is the pause between pages of a paged optional source (EUVD); tests only, zero is 1 s.
	SourcePageDelay time.Duration
	// Mirror returns the ClusterFeedMirror in force, read at the start of every round (D86); nil when none.
	Mirror   func(ctx context.Context) (*domain.FeedMirrorSpec, error)
	Interval time.Duration
	// OnlyDue makes a round sync only the feeds that are due (see FeedSyncer.due): the scheduler sets it, a manual sync does not.
	OnlyDue bool
	// CheckEvery is how often the scheduler looks for a feed that is due; zero is the interval or 30 minutes, whichever is
	// shorter. It is also how soon a failed feed is tried again.
	CheckEvery time.Duration
	HTTPClient *http.Client
	TempDir    string
	// StorageFull is storageMode full: the complete source record of every advisory is kept (vulnerability.source_payloads).
	StorageFull bool
	// SecretsDir is where token files must be (domain.FeedSecretsDir); tests only.
	SecretsDir string
	// AllowLoopback lets the default client reach 127.0.0.1; tests that serve a feed locally only (httpguard.go).
	AllowLoopback bool
	// NVDRetryBase is the first wait after a 429 or 503 that names no Retry-After; tests only, zero is 30 s.
	NVDRetryBase time.Duration
	guarded      bool // defaults() has already put the feed redirect rule on HTTPClient
	osvOff       bool // the ClusterFeed switches OSV off: storageMode full does not turn it back on
	// OnSynced runs after a round that changed the feeds, so findings can be re-scored (docs/16 D28).
	OnSynced func(ctx context.Context)
}

func (c *FeedConfig) secretsDir() string {
	if c.SecretsDir != "" {
		return c.SecretsDir
	}
	return domain.FeedSecretsDir
}

func (c *FeedConfig) defaults() {
	if c.KEVURL == "" {
		c.KEVURL = DefaultKEVURL
	}
	if c.EPSSURL == "" {
		c.EPSSURL = DefaultEPSSURL
	}
	if c.NVDURL == "" {
		c.NVDURL = DefaultNVDURL
	}
	if c.OSVBaseURL == "" {
		c.OSVBaseURL = DefaultOSVBaseURL
	}
	if c.Interval <= 0 {
		c.Interval = 6 * time.Hour
	}
	if c.HTTPClient == nil {
		c.HTTPClient = NewFeedHTTPClient(15*time.Minute, c.AllowLoopback)
	} else if !c.guarded {
		c.HTTPClient = withFeedRedirects(c.HTTPClient)
	}
	c.guarded = true
}

// get downloads url, refusing bodies over max bytes, and returns the body.
// applyMirror points each feed at its mirror. With egress deny, a feed that has no mirror is not read at all; it
// reports whether KEV and EPSS are to be skipped (NVD and OSV are switched off in the config itself).
func (c *FeedConfig) applyMirror(m *domain.FeedMirrorSpec, log *slog.Logger) (skipKEV, skipEPSS bool) {
	if m == nil {
		return false, false
	}
	deny := m.Egress == "deny"
	switch {
	case m.KEV != nil && !domain.On(m.KEV.Enabled):
		skipKEV = true // switched off in the resource
	case m.KEV != nil:
		c.KEVURL = m.KEV.URL
	case deny:
		skipKEV = true
	}
	switch {
	case m.EPSS != nil && !domain.On(m.EPSS.Enabled):
		skipEPSS = true
	case m.EPSS != nil:
		c.EPSSURL = m.EPSS.URL
	case deny:
		skipEPSS = true
	}
	switch {
	case m.NVD == nil:
		if deny {
			c.NVDDisabled = true
		}
	case !domain.On(m.NVD.Enabled):
		c.NVDDisabled = true
	case m.NVD.URL != "":
		c.NVDURL = m.NVD.URL
	case deny:
		c.NVDDisabled = true // a block with no address, and no public address allowed
	}
	if m.NVD != nil && domain.On(m.NVD.Enabled) && m.NVD.TokenFile != "" {
		// The key of the resource wins over the server's own file. A key that cannot be read leaves the sync
		// keyless, at NIST's lower rate, and says so; it must not stop the feed.
		if key, err := ReadFeedToken(m.NVD.TokenFile, c.secretsDir()); err != nil {
			log.Warn("feeds: nvd.tokenFile could not be read; NVD is synced at the keyless rate", "err", err)
		} else if key != "" {
			c.NVDAPIKey = key
		}
	}
	switch {
	case m.OSV == nil:
		if deny {
			c.OSVEcosystems = nil
		}
	case !domain.On(m.OSV.Enabled):
		c.OSVEcosystems = nil
		c.osvOff = true
	default:
		switch {
		case m.OSV.URL != "":
			c.OSVBaseURL = strings.TrimSuffix(m.OSV.URL, "/")
		case deny:
			c.OSVEcosystems = nil // no mirror, and the public address is not allowed
		}
		if len(m.OSV.Ecosystems) > 0 && !(deny && m.OSV.URL == "") {
			c.OSVEcosystems = append([]string(nil), m.OSV.Ecosystems...)
		}
	}
	c.StorageFull = m.StorageMode == "full" || m.StorageMode == "standalone"
	if (m.StorageMode == "full" || m.StorageMode == "standalone") && len(c.OSVEcosystems) == 0 && !deny && !c.osvOff {
		// When full local mirror is requested, sync major open-source ecosystems by default like Dependency-Track.
		c.OSVEcosystems = []string{"Go", "npm", "PyPI", "Maven"}
		log.Info("feeds: storageMode full; caching complete open-source vulnerability database locally", "ecosystems", c.OSVEcosystems)
	}
	if deny {
		log.Info("feeds: egress deny; feeds without a mirror are not read", "kev", !skipKEV, "epss", !skipEPSS, "nvd", !c.NVDDisabled, "osv", len(c.OSVEcosystems) > 0)
	}
	return skipKEV, skipEPSS
}

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
		return nil, fmt.Errorf("GET %s: status %d", redact(url), res.StatusCode)
	}
	if res.ContentLength > max {
		_ = res.Body.Close()
		return nil, fmt.Errorf("GET %s: %d bytes exceeds the %d byte limit", redact(url), res.ContentLength, max)
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
// wants reports whether this round is to run the feed: all of them, or the one named in Only.
func (c FeedConfig) wants(feed string) bool { return c.Only == "" || c.Only == feed }

func (s *FeedSyncer) SyncAll(ctx context.Context, cfg FeedConfig, log *slog.Logger) (err error) {
	cfg.defaults()
	s.mu.Lock()
	s.results = nil
	s.starts = map[string]time.Time{}
	s.began = 0
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		rs := s.results
		s.results = nil
		s.mu.Unlock()
		recordMetrics(context.WithoutCancel(ctx), rs)
		if cfg.OnRound != nil && len(rs) > 0 {
			// Not under the sync lock: telling every tenant can be slow, and a click meanwhile would be answered "busy".
			go func() {
				defer func() { _ = recover() }()
				cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				cfg.OnRound(cctx, rs)
			}()
		}
	}()
	var errs []error
	skipKEV, skipEPSS := false, false
	var mirror *domain.FeedMirrorSpec
	if cfg.Mirror != nil {
		m, err := cfg.Mirror(ctx)
		if err != nil {
			return fmt.Errorf("feeds: reading the ClusterFeedMirror: %w", err)
		}
		mirror = m
		skipKEV, skipEPSS = cfg.applyMirror(m, log)
	}

	if !cfg.wants("cisa_kev") {
		// another feed was asked for
	} else if skipKEV {
		// egress deny without a KEV mirror: not read (D86)
	} else if !s.due(ctx, cfg, "cisa_kev") {
		// fresh: a scheduled round leaves it
	} else {
		s.begin("cisa_kev")
		s.syncKEVRound(ctx, cfg, log, &errs)
	}

	if !cfg.wants("first_epss") {
		// another feed was asked for
	} else if skipEPSS {
		// egress deny without an EPSS mirror: not read (D86)
	} else if !s.due(ctx, cfg, "first_epss") {
		// fresh
	} else {
		s.begin("first_epss")
		s.syncEPSSRound(ctx, cfg, log, &errs)
	}

	if !cfg.NVDDisabled && cfg.wants("nvd") && s.due(ctx, cfg, "nvd") {
		started := time.Now()
		s.begin("nvd")
		n, err := s.syncNVD(ctx, cfg)
		if err != nil {
			s.recordFeedError(ctx, "nvd", err)
			errs = append(errs, fmt.Errorf("nvd: %w", err))
		} else if err := s.recordNVDSuccess(ctx, started, int64(n)); err != nil {
			errs = append(errs, err)
		} else {
			log.Info("feed synced", "feed", "nvd", "records", n)
		}
	}

	if len(cfg.OSVEcosystems) > 0 && cfg.wants("osv") && s.due(ctx, cfg, "osv") {
		s.begin("osv")
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

	// The optional sources (D88): exploitation evidence, SSVC, licensed feeds. Without a mirror, none is on, and the
	// rows of any source switched off are removed.
	errs = append(errs, s.syncOptionalAll(ctx, cfg, mirror, log)...)
	return errors.Join(errs...)
}

// syncEPSSRound downloads the daily EPSS file and applies it.
func (s *FeedSyncer) syncEPSSRound(ctx context.Context, cfg FeedConfig, log *slog.Logger, errs *[]error) {
	body, err := cfg.get(ctx, cfg.EPSSURL, maxEPSSBytes)
	if err != nil {
		s.recordFeedError(ctx, "first_epss", err)
		*errs = append(*errs, fmt.Errorf("epss: %w", err))
		return
	}
	defer func() { _ = body.Close() }()
	var r io.Reader = body
	if strings.HasSuffix(strings.ToLower(cfg.EPSSURL), ".gz") {
		gz, gerr := gzip.NewReader(body)
		if gerr != nil {
			s.recordFeedError(ctx, "first_epss", gerr) // the file could not be unpacked, which SyncEPSS never saw
			*errs = append(*errs, fmt.Errorf("epss: %w", gerr))
			return
		}
		r = gz
	}
	n, err := s.SyncEPSS(ctx, r)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("epss: %w", err))
		return
	}
	log.Info("feed synced", "feed", "first_epss", "records", n)
}

// syncKEVRound downloads the CISA catalogue unless the server says it has not changed since the last round (docs/33
// section 3.2: conditional GET), and applies it.
func (s *FeedSyncer) syncKEVRound(ctx context.Context, cfg FeedConfig, log *slog.Logger, errs *[]error) {
	body, next, notModified, err := cfg.getIfChanged(ctx, cfg.KEVURL, maxKEVBytes, s.loadConditional(ctx, "cisa_kev"))
	switch {
	case err != nil:
		s.recordFeedError(ctx, "cisa_kev", err)
		*errs = append(*errs, fmt.Errorf("kev: %w", err))
	case notModified:
		if err := s.recordNotModified(ctx, "cisa_kev"); err != nil {
			*errs = append(*errs, fmt.Errorf("kev: %w", err))
			return
		}
		log.Info("feed unchanged", "feed", "cisa_kev")
	default:
		n, err := s.SyncKEV(ctx, body)
		_ = body.Close()
		if err != nil {
			*errs = append(*errs, fmt.Errorf("kev: %w", err))
			return
		}
		if err := s.saveConditional(ctx, "cisa_kev", next); err != nil {
			log.Warn("feed: the KEV validators were not stored; the next round downloads the file again", "err", err)
		}
		log.Info("feed synced", "feed", "cisa_kev", "records", n)
	}
}

// osvCursor is what the OSV feed remembers between rounds, in feed_state.cursor: for each ecosystem, the validators of
// its archive (a server that says "not modified" saves the download) and the latest `modified` seen in it (a record
// that is no newer is not written again). It is dropped, and everything is rewritten, when the way rows are built
// changes (Rows) or the storage mode does (Full): a cursor must never skip a record the new rules would write
// differently.
type osvCursor struct {
	V          int                       `json:"v"`
	Rows       int                       `json:"rows"`
	Full       bool                      `json:"full"`
	Ecosystems map[string]osvEcoProgress `json:"ecosystems"`
}

type osvEcoProgress struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Modified     time.Time `json:"modified"` // the newest `modified` of a record in the archive
	Records      int       `json:"records"`  // records in the archive, so an unchanged round can still say how many there are
}

const (
	osvCursorVersion = 1
	// osvRowsVersion changes when what is written for a record changes (a new column filled, a new rule); bump it and
	// every ecosystem is rewritten once.
	osvRowsVersion = 1
)

func (s *FeedSyncer) loadOSVCursor(ctx context.Context, full bool) osvCursor {
	cur := osvCursor{V: osvCursorVersion, Rows: osvRowsVersion, Full: full, Ecosystems: map[string]osvEcoProgress{}}
	st, err := s.GetFeedState(ctx, SourceOSV)
	if err != nil || st == nil || st.Cursor == nil {
		return cur
	}
	var stored osvCursor
	if json.Unmarshal([]byte(*st.Cursor), &stored) != nil || stored.V != osvCursorVersion || stored.Rows != osvRowsVersion || stored.Full != full || stored.Ecosystems == nil {
		return cur
	}
	return stored
}

func (s *FeedSyncer) saveOSVCursor(ctx context.Context, cur osvCursor) error {
	b, _ := json.Marshal(cur)
	str := string(b)
	return s.saveCursor(ctx, SourceOSV, &str)
}

// syncOSVEcosystem downloads <base>/<ecosystem>/all.zip to a temporary file (a zip needs random access), then streams
// its JSON files into the database a thousand records at a time. It asks the server whether the archive changed since
// the last round, and writes only the records whose `modified` is newer than the last round's. It returns the number of
// records the archive holds.
func (s *FeedSyncer) syncOSVEcosystem(ctx context.Context, cfg FeedConfig, eco string) (int, error) {
	u := strings.TrimRight(cfg.OSVBaseURL, "/") + "/" + url.PathEscape(eco) + "/all.zip"
	cur := s.loadOSVCursor(ctx, cfg.StorageFull)
	prev, known := cur.Ecosystems[eco]
	var cond *conditional
	if known && prev.URL == u {
		cond = &conditional{URL: u, ETag: prev.ETag, LastModified: prev.LastModified}
	} else {
		prev = osvEcoProgress{} // another address (a mirror): its archive is not the one the cursor describes
	}
	body, next, notModified, err := cfg.getIfChanged(ctx, u, maxOSVBytes, cond)
	if err != nil {
		return 0, err
	}
	if notModified {
		return prev.Records, nil
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
	res, err := s.syncOSVZip(ctx, tmp.Name(), osvZipOptions{write: osvWrite{source: SourceOSV, full: cfg.StorageFull}, since: prev.Modified})
	if err != nil {
		return res.Written + res.Skipped, err
	}
	cur.Ecosystems[eco] = osvEcoProgress{URL: u, ETag: next.ETag, LastModified: next.LastModified, Modified: res.MaxModified, Records: res.Written + res.Skipped}
	if err := s.saveOSVCursor(ctx, cur); err != nil {
		slog.Warn("feeds: the OSV cursor was not stored; the next round reads the whole archive again", "ecosystem", eco, "err", err)
	}
	return res.Written + res.Skipped, nil
}

type osvZipOptions struct {
	write osvWrite
	since time.Time // zero writes every record; otherwise a record whose modified is not after it is skipped
}

type osvZipResult struct {
	Written, Skipped int
	MaxModified      time.Time
}

// SyncOSVZip applies every .json file of an OSV ecosystem archive.
func (s *FeedSyncer) SyncOSVZip(ctx context.Context, path string) (int, error) {
	res, err := s.syncOSVZip(ctx, path, osvZipOptions{write: osvWrite{source: SourceOSV}})
	return res.Written, err
}

func (s *FeedSyncer) syncOSVZip(ctx context.Context, path string, opt osvZipOptions) (osvZipResult, error) {
	var res osvZipResult
	zr, err := zip.OpenReader(path)
	if err != nil {
		return res, err
	}
	defer func() { _ = zr.Close() }()
	const chunkSize = 1000
	chunk := make([]OSVRecord, 0, chunkSize)
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		if err := s.writeOSVChunk(ctx, chunk, opt.write); err != nil {
			return err
		}
		res.Written += len(chunk)
		chunk = chunk[:0]
		return nil
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 32<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return res, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 32<<20))
		_ = rc.Close()
		if err != nil {
			continue
		}
		var rec OSVRecord
		if err := json.Unmarshal(b, &rec); err != nil || rec.ID == "" {
			continue // one malformed advisory must not stop the ecosystem
		}
		if mod := parseTime(rec.Modified); mod != nil {
			if mod.After(res.MaxModified) {
				res.MaxModified = *mod
			}
			if !opt.since.IsZero() && !mod.After(opt.since) {
				res.Skipped++ // written by an earlier round, and not changed since
				continue
			}
		}
		if opt.write.full {
			rec.raw = b
		}
		chunk = append(chunk, rec)
		if len(chunk) == chunkSize {
			if err := flush(); err != nil {
				return res, err
			}
		}
	}
	return res, flush()
}

// Lookup returns the intelligence for the given vulnerability ids as a small FeedStore, which
// the risk policy reads (D62). The query API calls it for the ids on one page, so nothing is held in memory.
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Exploitation evidence from the optional sources (D88), by id or alias.
	erows, err := s.pool.Query(ctx, `
		WITH req AS (SELECT DISTINCT unnest($1::text[]) AS rid),
		m AS (
			SELECT rid, rid AS vid FROM req
			UNION
			SELECT r.rid, a.vulnerability_id FROM req r JOIN vulnerability_alias a ON a.alias = r.rid
		)
		SELECT m.rid, bool_or(e.exploited),
		       COALESCE(array_agg(DISTINCT e.source) FILTER (WHERE e.exploited), '{}'),
		       max(CASE e.maturity WHEN 'weaponized' THEN 2 WHEN 'poc' THEN 1 ELSE 0 END)
		FROM m JOIN vulnerability_exploitation e ON e.vulnerability_id = m.vid
		GROUP BY m.rid`, req)
	if err != nil {
		return nil, fmt.Errorf("enrich: looking up exploitation: %w", err)
	}
	defer erows.Close()
	for erows.Next() {
		var e Exploitation
		var rank int32
		if err := erows.Scan(&e.ID, &e.Exploited, &e.Sources, &rank); err != nil {
			return nil, err
		}
		e.Maturity = [...]string{MaturityNone, MaturityPoC, MaturityWeaponized}[rank]
		fs.SetExploitation(e)
	}
	return fs, erows.Err()
}

// feedCheckEvery is how often the scheduler looks for a feed that is due, and so how soon a failed feed is tried again.
const feedCheckEvery = 30 * time.Minute

// RunScheduler keeps the feeds fresh until ctx ends. At start, and then every check (the interval or 30 minutes, whichever
// is shorter), it syncs each feed that is due: one that never synced, one whose last round failed, one whose interval has
// passed. A feed that is fresh is left alone, so a restart does not hit the upstream and a check that finds nothing costs one
// read of the state. Each feed is judged on its own state, so a feed switched on later, or one that failed while another
// succeeded, is not held back by the others. Only one replica syncs at a time: the others skip the round when they
// cannot take the advisory lock.
//
// A round that panics is logged and the next one runs on time: the scheduler never stops except when ctx ends.
func RunScheduler(ctx context.Context, pool *pgxpool.Pool, cfg FeedConfig, log *slog.Logger) {
	cfg.defaults()
	cfg.OnlyDue = true
	syncer := NewFeedSyncer(pool)
	lockKey := int64(fnvKey("rampart/feed-sync"))
	every := cfg.CheckEvery
	if every <= 0 {
		every = min(cfg.Interval, feedCheckEvery)
	}

	round := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("feed sync: a round panicked; the next one runs on schedule", "panic", fmt.Sprint(r))
			}
		}()
		conn, err := pool.Acquire(ctx)
		if err != nil {
			log.Warn("feed sync: no database connection", "error", err)
			return
		}
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
			conn.Release()
			return // another replica is syncing
		}
		defer unlockAndRelease(ctx, conn, lockKey)
		syncer.clearStaleSyncing(ctx)
		if err := syncer.SyncAll(ctx, cfg, log); err != nil {
			log.Warn("feed sync finished with errors", "error", err)
		}
		// Re-score when a feed was synced, even in a partial round: one feed may have changed. A check that found every
		// feed fresh changes nothing and must not trigger a re-score of everything.
		if cfg.OnSynced != nil && syncer.ranFeeds() > 0 {
			cfg.OnSynced(ctx)
		}
		syncer.recordFreshness(ctx)
	}

	syncer.recordFreshness(ctx) // the gauge is there from the start, not only after the first sync of this process
	round()
	t := time.NewTicker(every)
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
