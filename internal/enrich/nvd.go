package enrich

import (
	"encoding/json"
	"io"
	"strings"
)

// NVDEntry represents vulnerability metadata from the National Vulnerability Database (docs/21 §6.5).
type NVDEntry struct {
	CVEID        string   `json:"cve_id"`
	Description  string   `json:"description"`
	CVSSv3Score  float64  `json:"cvss_v3_score"`
	CVSSv3Vector string   `json:"cvss_v3_vector"`
	CWEIDs       []string `json:"cwe_ids"`
	References   []string `json:"references"`
}

// SetNVD stores an NVD entry in the feed store.
func (s *FeedStore) SetNVD(entry NVDEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nvd == nil {
		s.nvd = make(map[string]NVDEntry)
	}
	s.nvd[strings.ToUpper(strings.TrimSpace(entry.CVEID))] = entry
}

// GetNVD retrieves an NVD entry by CVE ID.
func (s *FeedStore) GetNVD(cve string) (NVDEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.nvd == nil {
		return NVDEntry{}, false
	}
	e, ok := s.nvd[strings.ToUpper(strings.TrimSpace(cve))]
	return e, ok
}

type nvdAPIResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// LoadNVD parses an NVD API 2.0 response and populates the store.
func (s *FeedStore) LoadNVD(r io.Reader) (int, error) {
	var resp nvdAPIResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return 0, err
	}

	count := 0
	for _, item := range resp.Vulnerabilities {
		cve := item.CVE
		if cve.ID == "" {
			continue
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		score := 0.0
		vector := ""
		if len(cve.Metrics.CvssMetricV31) > 0 {
			score = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			vector = cve.Metrics.CvssMetricV31[0].CvssData.VectorString
		}

		var cwes []string
		for _, w := range cve.Weaknesses {
			for _, wd := range w.Description {
				if strings.HasPrefix(strings.ToUpper(wd.Value), "CWE-") {
					cwes = append(cwes, wd.Value)
				}
			}
		}

		var refs []string
		for _, ref := range cve.References {
			if ref.URL != "" {
				refs = append(refs, ref.URL)
			}
		}

		entry := NVDEntry{
			CVEID:        cve.ID,
			Description:  desc,
			CVSSv3Score:  score,
			CVSSv3Vector: vector,
			CWEIDs:       cwes,
			References:   refs,
		}
		s.SetNVD(entry)
		count++
	}

	return count, nil
}
