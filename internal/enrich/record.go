package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rampart/internal/domain"

	"github.com/jackc/pgx/v5"
)

// VulnerabilityRecord is what the feeds know of one vulnerability (KEV, EPSS, OSV, NVD), whatever scanner or
// parser reported it. The finding page and the vulnerability page read it by id, so a CVE is described even
// when the report carried only its id (docs/11: GET /vulnerabilities/{id}).
type VulnerabilityRecord struct {
	ID              string          `json:"id"`
	Aliases         []string        `json:"aliases"`
	Summary         string          `json:"summary,omitempty"`
	Description     string          `json:"description,omitempty"`
	CWEs            []int           `json:"cwes"`
	CVSSScore       *float64        `json:"cvss_score,omitempty"`
	CVSSVector      string          `json:"cvss_vector,omitempty"`
	ScoringStatus   string          `json:"scoring_status,omitempty"` // "scored", "awaiting_analysis", "under_analysis", "unscored"
	NVDStatus       string          `json:"nvd_status,omitempty"`
	EPSSScore       *float64        `json:"epss_score,omitempty"`
	EPSSPercentile  *float64        `json:"epss_percentile,omitempty"`
	KEV             bool            `json:"kev"`
	KEVDateAdded    *time.Time      `json:"kev_date_added,omitempty"`
	KEVDueDate      *time.Time      `json:"kev_due_date,omitempty"`
	KEVRansomware   bool            `json:"kev_ransomware"`
	Published       *time.Time      `json:"published,omitempty"`
	Modified        *time.Time      `json:"modified,omitempty"`
	References      json.RawMessage `json:"references,omitempty"`
	FixedVersions   json.RawMessage `json:"fixed_versions,omitempty"`
	Links           []string        `json:"links"`
	ExploitSources  []string        `json:"exploited_by,omitempty"`
	ExploitMaturity string          `json:"exploit_maturity,omitempty"`
	UpdatedAt       *time.Time      `json:"updated_at,omitempty"`
}

// VulnerabilityLinks are the public pages of an id, for the analyst to read more: a CVE has NVD, the MITRE
// record and (when it is exploited) the CISA catalogue; every id has OSV. They are built from the id, so they
// exist even when no feed has the record.
func VulnerabilityLinks(id string, kev bool) []string {
	id = strings.TrimSpace(id)
	var out []string
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		out = append(out, "https://nvd.nist.gov/vuln/detail/"+id, "https://www.cve.org/CVERecord?id="+id)
		if kev {
			out = append(out, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
		}
	}
	if id != "" {
		out = append(out, "https://osv.dev/vulnerability/"+id)
	}
	return out
}

// readRecordFromDB reads the stored vulnerability record from PostgreSQL.
func (s *FeedSyncer) readRecordFromDB(ctx context.Context, id string) (*VulnerabilityRecord, error) {
	if s.pool == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}
	up := strings.ToUpper(id)
	var (
		r                         VulnerabilityRecord
		summary, description, vec *string
		cvss, epss, pct           *float64
		kevAdded, kevDue          *time.Time
		kevRansom                 *bool
		published, modified       *time.Time
		refs, fixed               []byte
		maturity                  *string
		updatedAt                 *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT v.id, v.aliases, v.summary, v.description, v.cwes, v.cvss_best_score::float8, v.cvss_best_vector,
		       v.epss_score::float8, v.epss_percentile::float8, v.kev_date_added::timestamptz, v.kev_due_date::timestamptz,
		       v.kev_ransomware, v.published, v.modified, v."references", v.fixed_versions, v.exploit_maturity,
		       v.updated_at
		FROM vulnerability v
		WHERE v.id = $1 OR v.id = $2 OR v.id = (SELECT vulnerability_id FROM vulnerability_alias WHERE alias IN ($1, $2) LIMIT 1)
		ORDER BY (v.id = $2) DESC, (v.id = $1) DESC LIMIT 1`, id, up).
		Scan(&r.ID, &r.Aliases, &summary, &description, &r.CWEs, &cvss, &vec, &epss, &pct, &kevAdded, &kevDue,
			&kevRansom, &published, &modified, &refs, &fixed, &maturity, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enrich: reading %s: %w", id, err)
	}
	r.Summary, r.Description, r.CVSSVector = deref(summary), deref(description), deref(vec)
	r.CVSSScore, r.EPSSScore, r.EPSSPercentile = cvss, epss, pct
	r.KEV, r.KEVDateAdded, r.KEVDueDate, r.KEVRansomware = kevAdded != nil, kevAdded, kevDue, kevRansom != nil && *kevRansom
	r.Published, r.Modified, r.UpdatedAt = published, modified, updatedAt
	if r.CVSSScore != nil && *r.CVSSScore > 0 {
		r.ScoringStatus = "scored"
	} else if strings.EqualFold(r.NVDStatus, "Under Analysis") {
		r.ScoringStatus = "under_analysis"
	} else if strings.HasPrefix(strings.ToUpper(r.ID), "CVE-") {
		r.ScoringStatus = "awaiting_analysis"
	} else {
		r.ScoringStatus = "unscored"
	}
	if len(refs) > 0 && string(refs) != "null" {
		r.References = refs
	}
	if len(fixed) > 0 && string(fixed) != "null" {
		r.FixedVersions = fixed
	}
	r.ExploitMaturity = deref(maturity)
	if r.Aliases == nil {
		r.Aliases = []string{}
	}
	if r.CWEs == nil {
		r.CWEs = []int{}
	}
	erows, err := s.pool.Query(ctx, `SELECT DISTINCT source FROM vulnerability_exploitation WHERE vulnerability_id = $1 AND exploited`, r.ID)
	if err == nil {
		defer erows.Close()
		for erows.Next() {
			var src string
			if erows.Scan(&src) == nil {
				r.ExploitSources = append(r.ExploitSources, src)
			}
		}
	}
	r.Links = VulnerabilityLinks(r.ID, r.KEV)
	return &r, nil
}

// Record reads the record of a vulnerability by its id or by one of its aliases (a GHSA id finds its CVE).
// Depending on AdvisoryMode (hybrid, live, stored), it serves cached data from the database and/or queries
// upstream advisory APIs live and stores the resulting report into the database (like a feed).
func (s *FeedSyncer) Record(ctx context.Context, id string) (*VulnerabilityRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}

	mode := s.AdvisoryMode()
	var (
		r   *VulnerabilityRecord
		err error
	)

	// In Hybrid or Stored mode, check the database first
	if mode != domain.AdvisoryModeLive && s.pool != nil {
		r, err = s.readRecordFromDB(ctx, id)
		if err != nil {
			return nil, err
		}
		// If found and has a narrative description or summary, check freshness
		if r != nil && (strings.TrimSpace(r.Description) != "" || strings.TrimSpace(r.Summary) != "") {
			isStale := false
			if r.UpdatedAt != nil {
				age := time.Since(*r.UpdatedAt)
				if (r.CVSSScore == nil || *r.CVSSScore == 0) && age > 1*time.Hour {
					isStale = true
				} else if age > 24*time.Hour {
					isStale = true
				}
			}
			if !isStale {
				return r, nil
			}
		}
	}

	// In Stored mode, do not perform live on-demand fetching
	if mode == domain.AdvisoryModeStored {
		return r, nil
	}

	// In Hybrid (when missing/empty) or Live mode: fetch live from upstream APIs and persist to database!
	liveRec, liveErr := s.FetchAndPersistLiveAdvisory(ctx, id)
	if liveErr == nil && liveRec != nil {
		return liveRec, nil
	}

	return r, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
