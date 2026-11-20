package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

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
	defer resp.Body.Close()

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

// FetchNVDLive queries NIST NVD API 2.0 for live CVE records.
func (c *AdvisoryClient) FetchNVDLive(ctx context.Context, cveID string, tokenFile string) (*NVDEntry, error) {
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

	if tokenFile != "" {
		if tokenBytes, err := os.ReadFile(tokenFile); err == nil {
			tok := strings.TrimSpace(string(tokenBytes))
			if tok != "" {
				req.Header.Set("apiKey", tok)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("advisory: nvd query failed for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: nvd returned status %d for %s", resp.StatusCode, cveID)
	}

	var nvdResp nvdAPIResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("advisory: decoding nvd json: %w", err)
	}
	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, nil
	}

	cve := nvdResp.Vulnerabilities[0].CVE
	entry := NVDEntry{CVEID: cve.ID, VulnStatus: cve.VulnStatus}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			entry.Description = d.Value
			break
		}
	}
	if entry.Description == "" && len(cve.Descriptions) > 0 {
		entry.Description = cve.Descriptions[0].Value
	}

	for _, m := range cve.Metrics.CvssMetricV31 {
		entry.CVSSv3Score = m.CvssData.BaseScore
		entry.CVSSv3Vector = m.CvssData.VectorString
		break
	}
	if entry.CVSSv3Score == 0 && len(cve.Metrics.CvssMetricV30) > 0 {
		entry.CVSSv3Score = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
		entry.CVSSv3Vector = cve.Metrics.CvssMetricV30[0].CvssData.VectorString
	}
	if entry.CVSSv3Score == 0 && len(cve.Metrics.CvssMetricV40) > 0 {
		entry.CVSSv3Score = cve.Metrics.CvssMetricV40[0].CvssData.BaseScore
		entry.CVSSv3Vector = cve.Metrics.CvssMetricV40[0].CvssData.VectorString
	}

	for _, w := range cve.Weaknesses {
		for _, desc := range w.Description {
			val := strings.TrimSpace(desc.Value)
			if strings.HasPrefix(strings.ToUpper(val), "CWE-") {
				entry.CWEIDs = append(entry.CWEIDs, strings.TrimPrefix(strings.ToUpper(val), "CWE-"))
			}
		}
	}

	for _, ref := range cve.References {
		if ref.URL != "" {
			entry.References = append(entry.References, ref.URL)
		}
	}

	return &entry, nil
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

// FetchAndPersistLiveAdvisory queries upstream advisory sources on demand and writes the
// result into PostgreSQL (vulnerability, vulnerability_alias, vulnerability_affected)
// exactly like a feed synchronization round.
func (s *FeedSyncer) FetchAndPersistLiveAdvisory(ctx context.Context, id string) (*VulnerabilityRecord, error) {
	client := s.getAdvisoryClient()
	if client == nil {
		return nil, nil
	}

	// 1. Try OSV.dev first (Google & GitHub Security Advisories)
	osvRec, err := client.FetchOSVLive(ctx, id)
	if err == nil && osvRec != nil && osvRec.ID != "" {
		// Persist to database if connected
		if s.pool != nil {
			w := osvWrite{source: "osv-live", full: true}
			_ = s.writeOSVChunk(ctx, []OSVRecord{*osvRec}, w)
			// Re-read canonical record from DB
			if dbRec, readErr := s.readRecordFromDB(ctx, id); readErr == nil && dbRec != nil {
				return dbRec, nil
			}
		}
		return synthesizeRecordFromOSV(osvRec), nil
	}

	// 2. If OSV did not have it and it's a CVE, query NIST NVD v2.0
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		nvdRec, nvdErr := client.FetchNVDLive(ctx, id, "")
		if nvdErr == nil && nvdRec != nil {
			if s.pool != nil {
				_ = s.persistNVDLive(ctx, nvdRec)
				if dbRec, readErr := s.readRecordFromDB(ctx, id); readErr == nil && dbRec != nil {
					return dbRec, nil
				}
			}
			return synthesizeRecordFromNVD(nvdRec), nil
		}
	}

	return nil, nil
}

func (s *FeedSyncer) persistNVDLive(ctx context.Context, entry *NVDEntry) error {
	if s.pool == nil || entry == nil || entry.CVEID == "" {
		return nil
	}

	var cwes []int
	for _, c := range entry.CWEIDs {
		if num, err := strconv.Atoi(c); err == nil {
			cwes = append(cwes, num)
		}
	}
	if cwes == nil {
		cwes = []int{}
	}

	var cvssScore *float64
	if entry.CVSSv3Score > 0 {
		cvssScore = &entry.CVSSv3Score
	}
	var cvssVector *string
	if entry.CVSSv3Vector != "" {
		cvssVector = &entry.CVSSv3Vector
	}

	refsJSON, _ := json.Marshal(entry.References)
	if len(refsJSON) == 0 {
		refsJSON = []byte("[]")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO vulnerability (
			id, description, cwes, cvss_best_score, cvss_best_vector, "references", updated_at
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET
			description = COALESCE(EXCLUDED.description, vulnerability.description),
			cwes = CASE WHEN cardinality(vulnerability.cwes) = 0 THEN EXCLUDED.cwes ELSE vulnerability.cwes END,
			cvss_best_score = COALESCE(vulnerability.cvss_best_score, EXCLUDED.cvss_best_score),
			cvss_best_vector = COALESCE(vulnerability.cvss_best_vector, EXCLUDED.cvss_best_vector),
			"references" = COALESCE(EXCLUDED."references", vulnerability."references"),
			updated_at = NOW()
	`, entry.CVEID, entry.Description, cwes, cvssScore, cvssVector, string(refsJSON))

	return err
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

func synthesizeRecordFromNVD(entry *NVDEntry) *VulnerabilityRecord {
	out := &VulnerabilityRecord{
		ID:          entry.CVEID,
		Aliases:     []string{},
		Description: entry.Description,
		Links:       VulnerabilityLinks(entry.CVEID, false),
		CWEs:        []int{},
		NVDStatus:   entry.VulnStatus,
	}
	if entry.CVSSv3Score > 0 {
		out.CVSSScore = &entry.CVSSv3Score
		out.ScoringStatus = "scored"
	} else if strings.EqualFold(entry.VulnStatus, "Under Analysis") {
		out.ScoringStatus = "under_analysis"
	} else {
		out.ScoringStatus = "awaiting_analysis"
	}
	out.CVSSVector = entry.CVSSv3Vector
	for _, c := range entry.CWEIDs {
		if num, err := strconv.Atoi(c); err == nil {
			out.CWEs = append(out.CWEs, num)
		}
	}
	if len(entry.References) > 0 {
		refsBytes, _ := json.Marshal(entry.References)
		out.References = refsBytes
	}
	now := time.Now().UTC()
	out.UpdatedAt = &now
	return out
}
