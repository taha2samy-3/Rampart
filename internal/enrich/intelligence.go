package enrich

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KEVEntry represents an entry from the CISA Known Exploited Vulnerabilities catalog (docs/06 §2).
type KEVEntry struct {
	CVEID                      string     `json:"cve_id"`
	VendorProject              string     `json:"vendor_project"`
	Product                    string     `json:"product"`
	VulnerabilityName          string     `json:"vulnerability_name"`
	DateAdded                  string     `json:"date_added"`
	ShortDescription           string     `json:"short_description"`
	RequiredAction             string     `json:"required_action"`
	DueDate                    *time.Time `json:"due_date,omitempty"`
	KnownRansomwareCampaignUse bool       `json:"known_ransomware_campaign_use"`
}

// EPSSScore represents an exploit prediction score from FIRST.org (docs/06 §2).
type EPSSScore struct {
	CVEID      string  `json:"cve_id"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// FeedStore maintains thread-safe in-memory threat intelligence feeds (D14, D19).
type FeedStore struct {
	mu   sync.RWMutex
	kev  map[string]KEVEntry
	epss map[string]EPSSScore
	nvd  map[string]NVDEntry
}

// NewFeedStore creates a new threat intelligence store.
func NewFeedStore() *FeedStore {
	return &FeedStore{
		kev:  make(map[string]KEVEntry),
		epss: make(map[string]EPSSScore),
		nvd:  make(map[string]NVDEntry),
	}
}

// SetKEV adds or updates a KEV entry.
func (s *FeedStore) SetKEV(entry KEVEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kev[strings.ToUpper(strings.TrimSpace(entry.CVEID))] = entry
}

// GetKEV retrieves a KEV entry by CVE ID.
func (s *FeedStore) GetKEV(cve string) (KEVEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.kev[strings.ToUpper(strings.TrimSpace(cve))]
	return entry, ok
}

// SetEPSS adds or updates an EPSS score.
func (s *FeedStore) SetEPSS(score EPSSScore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epss[strings.ToUpper(strings.TrimSpace(score.CVEID))] = score
}

// GetEPSS retrieves an EPSS score by CVE ID.
func (s *FeedStore) GetEPSS(cve string) (EPSSScore, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	score, ok := s.epss[strings.ToUpper(strings.TrimSpace(cve))]
	return score, ok
}

// LoadKEVJSON loads the official CISA KEV JSON catalog format.
func (s *FeedStore) LoadKEVJSON(r io.Reader) (int, error) {
	var catalog struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			ShortDescription           string `json:"shortDescription"`
			RequiredAction             string `json:"requiredAction"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(r).Decode(&catalog); err != nil {
		return 0, fmt.Errorf("enrich: failed to parse KEV JSON: %w", err)
	}

	count := 0
	for _, v := range catalog.Vulnerabilities {
		var parsedDueDate *time.Time
		if v.DueDate != "" {
			if t, err := time.Parse("2006-01-02", v.DueDate); err == nil {
				parsedDueDate = &t
			}
		}

		entry := KEVEntry{
			CVEID:                      v.CveID,
			VendorProject:              v.VendorProject,
			Product:                    v.Product,
			VulnerabilityName:          v.VulnerabilityName,
			DateAdded:                  v.DateAdded,
			ShortDescription:           v.ShortDescription,
			RequiredAction:             v.RequiredAction,
			DueDate:                    parsedDueDate,
			KnownRansomwareCampaignUse: strings.EqualFold(v.KnownRansomwareCampaignUse, "known"),
		}
		s.SetKEV(entry)
		count++
	}

	return count, nil
}

// LoadEPSSCSV loads the daily FIRST EPSS CSV file (cve,epss,percentile).
func (s *FeedStore) LoadEPSSCSV(r io.Reader) (int, error) {
	reader := csv.NewReader(bufio.NewReader(r))
	reader.Comment = '#'

	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("enrich: csv read error: %w", err)
		}

		if len(record) < 3 {
			continue
		}

		// Skip header line if present
		cve := strings.TrimSpace(record[0])
		if strings.EqualFold(cve, "cve") {
			continue
		}

		epssVal, err1 := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		percVal, err2 := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
		if err1 != nil || err2 != nil {
			continue
		}

		s.SetEPSS(EPSSScore{
			CVEID:      cve,
			EPSS:       epssVal,
			Percentile: percVal,
		})
		count++
	}

	return count, nil
}
