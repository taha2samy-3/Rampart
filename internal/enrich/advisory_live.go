package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"rampart/internal/domain"
)

// AdvisoryClient handles live on-demand querying of upstream vulnerability advisory providers.
type AdvisoryClient struct {
	HTTPClient *http.Client
	OSVURL     string
	NVDURL     string
}

// NewAdvisoryClient returns a new AdvisoryClient with standard production timeouts.
func NewAdvisoryClient() *AdvisoryClient {
	return &AdvisoryClient{
		HTTPClient: &http.Client{Timeout: 7 * time.Second},
		OSVURL:     "https://api.osv.dev/v1/vulns",
		NVDURL:     "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// FetchOSVLive queries OSV.dev for live vulnerability details by ID or alias.
func (c *AdvisoryClient) FetchOSVLive(ctx context.Context, id string) (*OSVRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}
	baseURL := c.OSVURL
	if baseURL == "" {
		baseURL = "https://api.osv.dev/v1/vulns"
	}
	reqURL := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Rampart-ASPM/Advisory-Live")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("advisory: osv query failed for %s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: osv returned status %d for %s", resp.StatusCode, id)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("advisory: reading osv body: %w", err)
	}

	var rec OSVRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("advisory: decoding osv json: %w", err)
	}
	rec.raw = body
	return &rec, nil
}

// nvdLiveResponse is the part of an NVD API 2.0 answer the live lookup shows when the record cannot be stored: it
// keeps each metric's type, so NVD's Primary score is preferred over a CNA's Secondary one.
type nvdLiveResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			VulnStatus   string `json:"vulnStatus"`
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
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdLive is one CVE as the live lookup read it: the entry (whose CVSSv3 fields hold only a 3.x metric), the best
// metric by the scheduled sync's rule (writeNVDPage: NVD's Primary in the newest version, 4.0 then 3.1 then 3.0, and a
// Secondary only when no version has a Primary) and the page in the form the scheduled sync stores.
type nvdLive struct {
	entry      NVDEntry
	bestScore  float64
	bestVector string
	page       *nvdPage
}

// pickMetric returns the first Primary metric across sets in order, else the first Secondary one.
func pickMetric(sets ...[]nvdMetric) *nvdMetric {
	for _, wantPrimary := range []bool{true, false} {
		for _, set := range sets {
			for i := range set {
				if (set[i].Type == "Primary") == wantPrimary {
					return &set[i]
				}
			}
		}
	}
	return nil
}

// FetchNVDLive queries NIST NVD API 2.0 for one CVE. apiKey is the key the scheduled sync uses (feeds.nvdApiKeyFile);
// empty is the keyless rate. CVSSv3Score and CVSSv3Vector hold a CVSS 3.1 or 3.0 metric only, NVD's Primary first: a
// 4.0 score is a different scale and never stands in for a 3.x one.
func (c *AdvisoryClient) FetchNVDLive(ctx context.Context, cveID string, apiKey string) (*NVDEntry, error) {
	l, err := c.fetchNVDLive(ctx, cveID, apiKey)
	if err != nil || l == nil {
		return nil, err
	}
	return &l.entry, nil
}

func (c *AdvisoryClient) fetchNVDLive(ctx context.Context, cveID string, apiKey string) (*nvdLive, error) {
	cveID = strings.TrimSpace(strings.ToUpper(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, nil
	}
	baseURL := c.NVDURL
	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	reqURL := fmt.Sprintf("%s?cveId=%s", baseURL, url.QueryEscape(cveID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Rampart-ASPM/Advisory-Live")
	req.Header.Set("Accept", "application/json")
	if k := strings.TrimSpace(apiKey); k != "" {
		req.Header.Set("apiKey", k)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("advisory: nvd query failed for %s: %w", cveID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: nvd returned status %d for %s", resp.StatusCode, cveID)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("advisory: reading nvd body: %w", err)
	}
	var nvdResp nvdLiveResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("advisory: decoding nvd json: %w", err)
	}
	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, nil
	}
	var page nvdPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("advisory: decoding nvd json: %w", err)
	}

	cve := nvdResp.Vulnerabilities[0].CVE
	out := &nvdLive{entry: NVDEntry{CVEID: cve.ID, VulnStatus: cve.VulnStatus}, page: &page}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			out.entry.Description = d.Value
			break
		}
	}
	if out.entry.Description == "" && len(cve.Descriptions) > 0 {
		out.entry.Description = cve.Descriptions[0].Value
	}
	if m := pickMetric(cve.Metrics.V31, cve.Metrics.V30); m != nil {
		out.entry.CVSSv3Score, out.entry.CVSSv3Vector = m.CvssData.BaseScore, m.CvssData.VectorString
	}
	if m := pickMetric(cve.Metrics.V40, cve.Metrics.V31, cve.Metrics.V30); m != nil {
		out.bestScore, out.bestVector = m.CvssData.BaseScore, m.CvssData.VectorString
	}
	for _, w := range cve.Weaknesses {
		for _, desc := range w.Description {
			val := strings.ToUpper(strings.TrimSpace(desc.Value))
			if strings.HasPrefix(val, "CWE-") {
				out.entry.CWEIDs = append(out.entry.CWEIDs, strings.TrimPrefix(val, "CWE-"))
			}
		}
	}
	for _, ref := range cve.References {
		if ref.URL != "" {
			out.entry.References = append(out.entry.References, ref.URL)
		}
	}
	return out, nil
}

// AdvisoryMode returns the active retrieval mode (hybrid, live, or stored).
func (s *FeedSyncer) AdvisoryMode() domain.AdvisoryMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.advisoryMode == "" {
		return domain.AdvisoryModeHybrid
	}
	return s.advisoryMode
}

// SetAdvisoryMode sets the advisory retrieval mode on the syncer.
func (s *FeedSyncer) SetAdvisoryMode(mode domain.AdvisoryMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advisoryMode = mode
}

// SetAdvisoryClient configures a custom AdvisoryClient (e.g. for testing with httptest).
func (s *FeedSyncer) SetAdvisoryClient(client *AdvisoryClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advisoryClient = client
}

func (s *FeedSyncer) getAdvisoryClient() *AdvisoryClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.advisoryClient == nil {
		s.advisoryClient = NewAdvisoryClient()
	}
	return s.advisoryClient
}

// ErrLiveFetchOff is returned by a refresh when the advisory mode is stored: this server does not reach the internet.
var ErrLiveFetchOff = errors.New("the advisory mode is stored: this server does not fetch advisories live")

// RefreshCooldownError is returned when the same vulnerability was fetched live less than the cooldown ago.
type RefreshCooldownError struct{ RetryAfter time.Duration }

func (e *RefreshCooldownError) Error() string {
	return fmt.Sprintf("this vulnerability was fetched live less than %s ago", DefaultRefreshCooldown)
}

// DefaultRefreshCooldown is how long a vulnerability is not fetched live again after a refresh (AGENTS.md section 4:
// a manual trigger is cooled down to spare the upstream quotas; NVD allows 5 keyless requests per 30 seconds).
const DefaultRefreshCooldown = 5 * time.Minute

// liveFetchTimeout bounds one live fetch (OSV, then NVD, then the write). It is detached from the caller's request
// so that one caller leaving does not fail the others waiting on the same fetch.
const liveFetchTimeout = 45 * time.Second

// LiveAdvisory is the "Refresh" button of a vulnerability page (docs/44, docs/51 step 1.5). It reads through the
// embedded FeedSyncer (the application role: Lookup and Record, which never fetch live) and fetches live only when
// Refresh is called: one fetch per vulnerability at a time (single flight), and not again within the cooldown.
//
// The live result is written with writer, a FeedSyncer on the system pool: the application role may not write the
// global vulnerability table (00001_initial_schema.sql REVOKE ... ON vulnerability FROM rampart_app). Without a
// system pool (database.systemUrl) the record is shown but not stored, and the log says so.
type LiveAdvisory struct {
	*FeedSyncer
	writer    *FeedSyncer
	nvdAPIKey string
	cooldown  time.Duration
	now       func() time.Time
	log       *slog.Logger

	mu       sync.Mutex
	last     map[string]time.Time // when each id was last fetched live
	inflight map[string]bool
	group    singleflight.Group
}

// NewLiveAdvisory builds the refresh path. reader serves the page views; writePool is the system pool (nil: results
// are not stored); nvdAPIKey is the key the scheduled sync uses (empty: keyless).
func NewLiveAdvisory(reader *FeedSyncer, writePool *pgxpool.Pool, nvdAPIKey string, log *slog.Logger) *LiveAdvisory {
	if reader == nil {
		reader = NewFeedSyncer(nil)
	}
	if log == nil {
		log = slog.Default()
	}
	l := &LiveAdvisory{FeedSyncer: reader, nvdAPIKey: strings.TrimSpace(nvdAPIKey), cooldown: DefaultRefreshCooldown,
		now: time.Now, log: log, last: map[string]time.Time{}, inflight: map[string]bool{}}
	if writePool != nil {
		l.writer = NewFeedSyncer(writePool)
	}
	return l
}

// SetCooldown changes the cooldown (tests).
func (l *LiveAdvisory) SetCooldown(d time.Duration) { l.mu.Lock(); l.cooldown = d; l.mu.Unlock() }

// SetClock changes the clock (tests).
func (l *LiveAdvisory) SetClock(now func() time.Time) { l.mu.Lock(); l.now = now; l.mu.Unlock() }

// Persists says whether a live result is stored (a system pool was given).
func (l *LiveAdvisory) Persists() bool { return l.writer != nil }

// Refresh fetches one vulnerability live, under single flight and the cooldown. A caller that arrives while a fetch
// of the same id is running waits for it and gets its result; one that arrives after it, within the cooldown, gets
// a *RefreshCooldownError. A failed fetch starts the cooldown too: a throttled upstream must not be asked again at once.
func (l *LiveAdvisory) Refresh(ctx context.Context, id string) (*VulnerabilityRecord, error) {
	key := strings.ToUpper(strings.TrimSpace(id))
	if key == "" {
		return nil, nil
	}
	if l.AdvisoryMode() == domain.AdvisoryModeStored {
		return nil, ErrLiveFetchOff
	}
	l.mu.Lock()
	now := l.now()
	if !l.inflight[key] {
		if t, ok := l.last[key]; ok && now.Sub(t) < l.cooldown {
			l.mu.Unlock()
			return nil, &RefreshCooldownError{RetryAfter: l.cooldown - now.Sub(t)}
		}
		l.inflight[key] = true
		l.last[key] = now
		l.prune(now)
	}
	l.mu.Unlock()

	v, err, _ := l.group.Do(key, func() (any, error) {
		defer func() {
			l.mu.Lock()
			delete(l.inflight, key)
			l.mu.Unlock()
		}()
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), liveFetchTimeout)
		defer cancel()
		return l.Fetch(fctx, id)
	})
	if err != nil {
		return nil, err
	}
	rec, _ := v.(*VulnerabilityRecord)
	return rec, nil
}

// prune drops the ids whose cooldown has passed, so the map does not grow with every id ever refreshed. l.mu is held.
func (l *LiveAdvisory) prune(now time.Time) {
	if len(l.last) < 1024 {
		return
	}
	for k, t := range l.last {
		if now.Sub(t) >= l.cooldown && !l.inflight[k] {
			delete(l.last, k)
		}
	}
}

// Fetch queries the upstream advisory sources for one id, with no single flight or cooldown (Refresh adds them),
// and stores the result through the system pool when there is one: OSV first, then NVD for a CVE that OSV does not
// have. The stored record is read back, so the answer is what the next page view shows.
func (l *LiveAdvisory) Fetch(ctx context.Context, id string) (*VulnerabilityRecord, error) {
	client := l.getAdvisoryClient()
	if client == nil {
		return nil, fmt.Errorf("advisory sync client unavailable")
	}
	var upstreamErrs []string

	// 1. OSV.dev (GitHub Security Advisories and the ecosystems' own databases).
	osvRec, err := client.FetchOSVLive(ctx, id)
	if err != nil {
		upstreamErrs = append(upstreamErrs, fmt.Sprintf("OSV: %v", err))
	} else if osvRec != nil && osvRec.ID != "" {
		stored := false
		if l.writer != nil {
			if werr := l.writer.writeOSVChunk(ctx, []OSVRecord{*osvRec}, osvWrite{source: "osv-live", full: true}); werr != nil {
				l.log.Warn("advisory refresh: storing the OSV record failed; it is shown but not stored", "id", id, "error", werr)
			} else {
				stored = true
			}
		} else {
			l.log.Warn("advisory refresh: no system database pool (database.systemUrl), so the live record is shown but not stored", "id", id)
		}
		if rec := l.readBack(ctx, id, stored); rec != nil {
			return rec, nil
		}
		rec := synthesizeRecordFromOSV(osvRec)
		rec.SyncStatus = "success"
		return rec, nil
	}

	// 2. NIST NVD 2.0 for a CVE that OSV does not have, with the scheduled sync's API key.
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-") {
		nvd, nvdErr := client.fetchNVDLive(ctx, id, l.nvdAPIKey)
		if nvdErr != nil {
			upstreamErrs = append(upstreamErrs, fmt.Sprintf("NIST NVD: %v", nvdErr))
		} else if nvd != nil {
			stored := false
			if l.writer != nil {
				// The same write as the scheduled NVD sync, so a live row and a synced row cannot differ.
				if _, werr := l.writer.writeNVDPage(ctx, nvd.page); werr != nil {
					l.log.Warn("advisory refresh: storing the NVD record failed; it is shown but not stored", "id", id, "error", werr)
				} else {
					stored = true
				}
			} else {
				l.log.Warn("advisory refresh: no system database pool (database.systemUrl), so the live record is shown but not stored", "id", id)
			}
			if rec := l.readBack(ctx, id, stored); rec != nil {
				return rec, nil
			}
			rec := synthesizeRecordFromNVD(nvd)
			rec.SyncStatus = "success"
			return rec, nil
		}
	}

	if len(upstreamErrs) > 0 {
		return nil, fmt.Errorf("upstream sync encountered error(s): %s", strings.Join(upstreamErrs, "; "))
	}
	return nil, nil
}

// readBack reads the stored record after a write, or nil when nothing was stored or it cannot be read.
func (l *LiveAdvisory) readBack(ctx context.Context, id string, stored bool) *VulnerabilityRecord {
	if !stored {
		return nil
	}
	rec, err := l.readRecordFromDB(ctx, id)
	if err != nil {
		l.log.Warn("advisory refresh: reading the stored record back failed", "id", id, "error", err)
		return nil
	}
	if rec != nil {
		rec.SyncStatus = "success"
	}
	return rec
}

func synthesizeRecordFromOSV(rec *OSVRecord) *VulnerabilityRecord {
	out := &VulnerabilityRecord{
		ID:          rec.ID,
		Aliases:     rec.Aliases,
		Summary:     rec.Summary,
		Description: rec.Details,
		Links:       VulnerabilityLinks(rec.ID, false),
		CWEs:        []int{},
	}
	if out.Aliases == nil {
		out.Aliases = []string{}
	}
	if pubTime := parseTime(rec.Published); pubTime != nil {
		out.Published = pubTime
	}
	if modTime := parseTime(rec.Modified); modTime != nil {
		out.Modified = modTime
	}
	_, bestVector := osvCVSS(rec.Severity, "osv")
	out.CVSSVector = bestVector
	if len(rec.References) > 0 {
		out.References = rec.References
	}
	if out.CVSSVector != "" {
		out.ScoringStatus = "scored"
	} else if strings.HasPrefix(strings.ToUpper(rec.ID), "CVE-") {
		out.ScoringStatus = "awaiting_analysis"
	} else {
		out.ScoringStatus = "unscored"
	}
	now := time.Now().UTC()
	out.UpdatedAt = &now
	return out
}

func synthesizeRecordFromNVD(l *nvdLive) *VulnerabilityRecord {
	entry := l.entry
	out := &VulnerabilityRecord{
		ID:          entry.CVEID,
		Aliases:     []string{},
		Description: entry.Description,
		Links:       VulnerabilityLinks(entry.CVEID, false),
		CWEs:        []int{},
		NVDStatus:   entry.VulnStatus,
	}
	// The record's score is the best metric, by the rule the stored row follows (it may be a 4.0 score).
	if l.bestScore > 0 {
		score := l.bestScore
		out.CVSSScore = &score
		out.CVSSVector = l.bestVector
		out.ScoringStatus = "scored"
	} else if strings.EqualFold(entry.VulnStatus, "Under Analysis") {
		out.ScoringStatus = "under_analysis"
	} else {
		out.ScoringStatus = "awaiting_analysis"
	}
	for _, c := range entry.CWEIDs {
		if num, err := strconv.Atoi(c); err == nil {
			out.CWEs = append(out.CWEs, num)
		}
	}
	if len(entry.References) > 0 {
		if refsBytes, err := json.Marshal(entry.References); err == nil {
			out.References = refsBytes
		}
	}
	now := time.Now().UTC()
	out.UpdatedAt = &now
	return out
}
