package enrich

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rampart/internal/domain"
)

// Public addresses of the optional sources (D88). Each can be replaced by a mirror in the ClusterFeedMirror.
const (
	DefaultVulnrichmentURL = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"
	DefaultExploitDBURL    = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	DefaultMetasploitURL   = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
	DefaultEUVDURL         = "https://euvdservices.enisa.europa.eu"
	DefaultVulnCheckURL    = "https://api.vulncheck.com"

	maxSourceBytes       = 512 << 20
	maxVulnrichmentBytes = 2 << 30
	maxRecordBytes       = 4 << 20
	euvdPageSize         = 100
	euvdMaxPages         = 2000
	euvdDelay            = time.Second // ENISA publishes no limit; one request a second is polite
	maxTokenBytes        = 8 << 10
)

// Source labels, as stored in vulnerability_exploitation.source and feed_state.feed.
const (
	SourceVulnrichment = "vulnrichment"
	SourceExploitDB    = "exploitdb"
	SourceMetasploit   = "metasploit"
	SourceEUVD         = "euvd"
	SourceVulnCheckKEV = "vulncheck_kev"
	SourceOSV          = "osv"
)

// optionalSource is one source switched on for this round, resolved from the ClusterFeedMirror.
type optionalSource struct {
	name   string
	url    string
	token  string
	format string // custom feeds only
	push   bool   // a feed plugin pushes the file (D94); there is no url to pull
}

// optionalSources resolves the sources the mirror switches on. With egress deny, a source without its own URL is
// not read (and is off). A token file that cannot be read fails that source, not the round; it stays on, in keep, so
// its last good rows are not pruned.
func optionalSources(m *domain.FeedMirrorSpec, secretsDir string) (srcs []optionalSource, keep []string, errs []error) {
	keep = []string{}
	if m == nil {
		return nil, keep, nil
	}
	deny := m.Egress == "deny"
	add := func(name string, fs *domain.FeedSource, def string) {
		if fs == nil || fs.Off() {
			return // absent or switched off: not read, and not kept, so its rows are removed
		}
		u := fs.URL
		if u == "" {
			if deny {
				return
			}
			u = def
		}
		keep = append(keep, name)
		tok, err := ReadFeedToken(fs.TokenFile, secretsDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			return
		}
		srcs = append(srcs, optionalSource{name: name, url: u, token: tok})
	}
	add(SourceVulnrichment, m.Vulnrichment, DefaultVulnrichmentURL)
	add(SourceExploitDB, m.ExploitDB, DefaultExploitDBURL)
	add(SourceMetasploit, m.Metasploit, DefaultMetasploitURL)
	add(SourceEUVD, m.EUVD, DefaultEUVDURL)
	add(SourceVulnCheckKEV, m.VulnCheckKEV, DefaultVulnCheckURL)
	for _, c := range m.Custom {
		if c.Off() {
			continue
		}
		keep = append(keep, c.Name)
		tok, err := ReadFeedToken(c.TokenFile, secretsDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
			continue
		}
		srcs = append(srcs, optionalSource{name: c.Name, url: c.URL, token: tok, format: c.Format, push: c.PushTokenFile != ""})
	}
	return srcs, keep, errs
}

// ReadFeedToken reads a token from a file inside dir (domain.FeedSecretsDir for a pulled feed, domain.FeedPushTokensDir
// for a pushed one). The path is checked again here, when the file is read, whatever the resource said when it was
// stored: it must be absolute and clean, lie in dir, and, once the symbolic links of a Secret mount are resolved,
// still lie in dir and name a regular file. A file anywhere else in the pod (the session key, a database password) is
// never read, so a feed's address cannot be made to receive it.
func ReadFeedToken(p, dir string) (string, error) {
	if p == "" {
		return "", nil
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasPrefix(p, strings.TrimRight(dir, "/")+"/") {
		return "", fmt.Errorf("the token file %q is not a file under %s", p, dir)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("reading the token file: %w", err)
	}
	rdir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		rdir = dir
	}
	if !domain.FeedTokenPathAllowed(resolved, rdir) && !domain.FeedTokenPathAllowed(resolved, dir) {
		return "", fmt.Errorf("the token file %q resolves outside %s", p, dir)
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", fmt.Errorf("reading the token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("the token file %q is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTokenBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// getWith downloads u with an optional bearer token, refusing bodies over max bytes.
func (c *FeedConfig) getWith(ctx context.Context, u, token string, max int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rampart-feed-sync")
	req.Header.Set("Accept", "application/json, */*")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", redact(u), res.StatusCode)
	}
	if res.ContentLength > max {
		_ = res.Body.Close()
		return nil, fmt.Errorf("GET %s: %d bytes exceeds the %d byte limit", redact(u), res.ContentLength, max)
	}
	return &limitedBody{Reader: io.LimitReader(res.Body, max+1), c: res.Body, max: max}, nil
}

// redact drops the query, which on a signed download URL is a credential, and any user name and password in the URL.
func redact(u string) string {
	if p, err := url.Parse(u); err == nil {
		p.RawQuery = ""
		p.User = nil
		return p.String()
	}
	return "the URL"
}

// syncOptional runs one source and returns the number of records it wrote.
func (s *FeedSyncer) syncOptional(ctx context.Context, cfg FeedConfig, src optionalSource) (int, error) {
	switch {
	case src.push:
		return s.syncPushed(ctx, src)
	case src.name == SourceExploitDB:
		return s.syncRows(ctx, cfg, src, maxSourceBytes, ParseExploitDB)
	case src.name == SourceMetasploit:
		return s.syncRows(ctx, cfg, src, maxSourceBytes, ParseMetasploit)
	case src.name == SourceVulnCheckKEV:
		return s.syncVulnCheckKEV(ctx, cfg, src)
	case src.name == SourceEUVD:
		return s.syncEUVD(ctx, cfg, src)
	case src.name == SourceVulnrichment:
		return s.syncVulnrichment(ctx, cfg, src)
	case src.format == domain.CustomFeedIntelJSONL:
		return s.syncRows(ctx, cfg, src, maxSourceBytes, ParseIntelJSONL)
	case src.format == domain.CustomFeedOSVZip:
		path, err := s.download(ctx, cfg, src.url, src.token, maxOSVBytes)
		if err != nil {
			return 0, err
		}
		defer func() { _ = os.Remove(path) }()
		res, err := s.syncOSVZip(ctx, path, osvZipOptions{write: osvWrite{source: src.name, full: cfg.StorageFull}})
		return res.Written + res.Skipped, err
	}
	return 0, fmt.Errorf("unknown source %q", src.name)
}

func (s *FeedSyncer) syncRows(ctx context.Context, cfg FeedConfig, src optionalSource, max int64, parse func(io.Reader) ([]ExploitRow, error)) (int, error) {
	body, err := cfg.getWith(ctx, src.url, src.token, max)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()
	rows, err := parse(body)
	if err != nil {
		return 0, err
	}
	return s.ReplaceExploitation(ctx, src.name, rows)
}

// download saves a body to a temporary file (a zip needs random access) and returns its path.
func (s *FeedSyncer) download(ctx context.Context, cfg FeedConfig, u, token string, max int64) (string, error) {
	body, err := cfg.getWith(ctx, u, token, max)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()
	tmp, err := os.CreateTemp(cfg.TempDir, "feed-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// syncVulnCheckKEV asks the backup endpoint for a signed link, downloads the archive, checks its SHA-256 and reads
// every JSON file in it (docs.vulncheck.com, API backup and community/vulncheck-kev).
func (s *FeedSyncer) syncVulnCheckKEV(ctx context.Context, cfg FeedConfig, src optionalSource) (int, error) {
	body, err := cfg.getWith(ctx, strings.TrimRight(src.url, "/")+"/v3/backup/vulncheck-kev", src.token, 1<<20)
	if err != nil {
		return 0, err
	}
	var meta struct {
		Data []struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"data"`
	}
	err = json.NewDecoder(body).Decode(&meta)
	_ = body.Close()
	if err != nil {
		return 0, fmt.Errorf("backup response: %w", err)
	}
	if len(meta.Data) == 0 || meta.Data[0].URL == "" {
		return 0, errors.New("the backup response has no download link")
	}
	// The signed link carries its own credential; the API token is not sent to the storage host.
	path, err := s.download(ctx, cfg, meta.Data[0].URL, "", maxSourceBytes)
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.Remove(path) }()
	if want := strings.ToLower(meta.Data[0].SHA256); want != "" {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return 0, err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return 0, fmt.Errorf("the archive's SHA-256 is %s, the API said %s; refused", got, want)
		}
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = zr.Close() }()
	var rows []ExploitRow
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		r, err := ParseVulnCheckKEV(io.LimitReader(rc, maxSourceBytes))
		_ = rc.Close()
		if err != nil {
			return 0, err
		}
		rows = append(rows, r...)
	}
	return s.ReplaceExploitation(ctx, src.name, mergeRows(rows))
}

// syncEUVD pages through the exploited vulnerabilities of ENISA's EUVD API.
func (s *FeedSyncer) syncEUVD(ctx context.Context, cfg FeedConfig, src optionalSource) (int, error) {
	delay := cfg.SourcePageDelay
	if delay == 0 {
		delay = euvdDelay
	}
	var rows []ExploitRow
	var aliases [][2]string
	for page := 0; page < euvdMaxPages; page++ {
		q := url.Values{"exploited": {"true"}, "size": {strconv.Itoa(euvdPageSize)}, "page": {strconv.Itoa(page)}}
		body, err := cfg.getWith(ctx, strings.TrimRight(src.url, "/")+"/api/vulnerabilities?"+q.Encode(), src.token, 32<<20)
		if err != nil {
			return 0, err
		}
		var p euvdPage
		err = json.NewDecoder(body).Decode(&p)
		_ = body.Close()
		if err != nil {
			return 0, fmt.Errorf("page %d: %w", page, err)
		}
		r, a := euvdRows(&p)
		rows, aliases = append(rows, r...), append(aliases, a...)
		if len(p.Items) == 0 || (page+1)*euvdPageSize >= p.Total {
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(delay):
		}
	}
	n, err := s.ReplaceExploitation(ctx, src.name, mergeRows(rows))
	if err != nil {
		return n, err
	}
	return n, s.addAliases(ctx, aliases)
}

// addAliases records EUVD ids as aliases of the CVEs Rampart already knows, so a finding that carries an EUVD id
// reads the CVE's intelligence. An alias already pointing elsewhere is left alone.
func (s *FeedSyncer) addAliases(ctx context.Context, pairs [][2]string) error {
	batch := &pgx.Batch{}
	for _, p := range pairs {
		batch.Queue(`INSERT INTO vulnerability_alias (alias, vulnerability_id)
			SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM vulnerability WHERE id = $2)
			ON CONFLICT (alias) DO NOTHING`, p[0], p[1])
	}
	if batch.Len() == 0 {
		return nil
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// syncVulnrichment reads CISA's Vulnrichment archive: SSVC into vulnerability.ssvc, the Exploitation decision into
// the exploitation rows, and CISA's CVSS and CWEs where NVD has none (they never replace NVD's).
func (s *FeedSyncer) syncVulnrichment(ctx context.Context, cfg FeedConfig, src optionalSource) (int, error) {
	path, err := s.download(ctx, cfg, src.url, src.token, maxVulnrichmentBytes)
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.Remove(path) }()
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = zr.Close() }()
	var rows []ExploitRow
	batch := &pgx.Batch{}
	written := 0
	flush := func() error {
		if batch.Len() == 0 {
			return nil
		}
		err := s.pool.SendBatch(ctx, batch).Close()
		written += batch.Len()
		batch = &pgx.Batch{}
		return err
	}
	for _, f := range zr.File {
		base := f.Name[strings.LastIndex(f.Name, "/")+1:]
		if !strings.HasPrefix(base, "CVE-") || !strings.HasSuffix(base, ".json") || f.UncompressedSize64 > maxRecordBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return written, err
		}
		rec, ok, err := ParseVulnrichmentRecord(io.LimitReader(rc, maxRecordBytes))
		_ = rc.Close()
		if err != nil || !ok {
			continue // one malformed record must not stop the archive
		}
		if r, ok := rec.exploitRow(); ok {
			rows = append(rows, r)
		}
		queueVulnrichment(batch, rec)
		if batch.Len() >= 1000 {
			if err := flush(); err != nil {
				return written, fmt.Errorf("writing vulnrichment: %w", err)
			}
		}
	}
	if err := flush(); err != nil {
		return written, fmt.Errorf("writing vulnrichment: %w", err)
	}
	if _, err := s.ReplaceExploitation(ctx, src.name, mergeRows(rows)); err != nil {
		return written, err
	}
	return written, nil
}

func queueVulnrichment(batch *pgx.Batch, rec VulnrichmentRecord) {
	var score *float64
	var vector *string
	if rec.CVSS != nil {
		score, vector = &rec.CVSS.Score, &rec.CVSS.Vector
	}
	cwes := rec.CWEs
	if cwes == nil {
		cwes = []int{}
	}
	var ssvc any
	if len(rec.SSVC) > 0 && !bytes.Equal(rec.SSVC, []byte("null")) {
		ssvc = string(rec.SSVC)
	}
	batch.Queue(`
		INSERT INTO vulnerability (id, ssvc, cwes, cvss_best_score, cvss_best_vector, updated_at)
		VALUES ($1, $2::jsonb, $3, $4, $5, NOW())
		ON CONFLICT (id) DO UPDATE SET
			ssvc             = COALESCE(EXCLUDED.ssvc, vulnerability.ssvc),
			cwes             = CASE WHEN cardinality(vulnerability.cwes) = 0 THEN EXCLUDED.cwes ELSE vulnerability.cwes END,
			cvss_best_score  = COALESCE(vulnerability.cvss_best_score, EXCLUDED.cvss_best_score),
			cvss_best_vector = CASE WHEN vulnerability.cvss_best_score IS NULL THEN EXCLUDED.cvss_best_vector ELSE vulnerability.cvss_best_vector END,
			updated_at       = NOW()`,
		rec.ID, ssvc, cwes, score, vector)
}

// ReplaceExploitation makes rows the complete list of what source says, in one transaction: a CVE the source no
// longer lists stops counting. It returns the number of rows written.
func (s *FeedSyncer) ReplaceExploitation(ctx context.Context, source string, rows []ExploitRow) (int, error) {
	rows = mergeRows(rows)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_exploitation WHERE source = $1`, source); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	n, err := tx.CopyFrom(ctx, pgx.Identifier{"vulnerability_exploitation"},
		[]string{"vulnerability_id", "source", "exploited", "maturity", "reported_at", "evidence_url", "updated_at"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			var ev *string
			if r.Evidence != "" {
				ev = &r.Evidence
			}
			return []any{r.ID, source, r.Exploited, r.Maturity, r.Reported, ev, now}, nil
		}))
	if err != nil {
		return 0, fmt.Errorf("writing %s exploitation: %w", source, err)
	}
	return int(n), tx.Commit(ctx)
}

// pruneSources removes the rows of sources no longer switched on, so turning a source off removes its effect on
// scores. Sources that failed this round keep their last good rows.
func (s *FeedSyncer) pruneSources(ctx context.Context, keep []string) error {
	if keep == nil {
		keep = []string{}
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM vulnerability_exploitation WHERE source <> ALL($1::text[])`, keep)
	return err
}

// syncOptionalAll runs every optional source the mirror switches on. One failing source does not stop the others.
func (s *FeedSyncer) syncOptionalAll(ctx context.Context, cfg FeedConfig, m *domain.FeedMirrorSpec, log *slog.Logger) []error {
	srcs, keep, errs := optionalSources(m, cfg.secretsDir())
	if cfg.Only == "" { // a one-feed round must not prune the others
		if err := s.pruneSources(ctx, keep); err != nil {
			errs = append(errs, fmt.Errorf("pruning sources: %w", err))
		}
	}
	for _, src := range srcs {
		if !cfg.wants(src.name) || !s.due(ctx, cfg, src.name) {
			continue
		}
		s.begin(src.name)
		n, err := s.syncOptional(ctx, cfg, src)
		if err != nil {
			s.recordFeedError(ctx, src.name, err)
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		if err := s.recordFeedSuccess(ctx, src.name, int64(n)); err != nil {
			errs = append(errs, err)
			continue
		}
		log.Info("feed synced", "feed", src.name, "records", n)
	}
	return errs
}

// syncPushed loads the file a feed plugin last pushed (D94). The API checked the token and the whole file before
// staging it; it is parsed again here, because this is the writer. Nothing staged yet is not an error: the feed's
// earlier rows stay (the source is in keep).
func (s *FeedSyncer) syncPushed(ctx context.Context, src optionalSource) (int, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT body FROM feed_push WHERE feed = $1`, src.name).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	rows, err := ParseIntelJSONL(bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	return s.ReplaceExploitation(ctx, src.name, rows)
}
