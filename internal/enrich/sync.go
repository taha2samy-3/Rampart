package enrich

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/domain"
)

// FeedState records the synchronization status of an external threat intelligence feed.
type FeedState = domain.FeedState

// OSVRecord represents the Open Source Vulnerabilities schema.
type OSVRecord struct {
	ID         string          `json:"id"`
	Aliases    []string        `json:"aliases"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Published  string          `json:"published"`
	Modified   string          `json:"modified"`
	Affected   json.RawMessage `json:"affected"`
	References json.RawMessage `json:"references"`
	Withdrawn  string          `json:"withdrawn"`
	Severity   []osvSeverity   `json:"severity"`

	raw json.RawMessage // the record as read, kept when the sync stores full payloads (storageMode full)
}

// osvWrite says how a batch of OSV records is written.
type osvWrite struct {
	source string // the feed that wrote them: osv, or the name of a custom osv-zip feed; recorded on the aliases
	full   bool   // storageMode full: keep the whole record in vulnerability.source_payloads
}

// FeedSyncer writes global intelligence tables as rampart_system (D19).
type FeedSyncer struct {
	pool *pgxpool.Pool

	mu      sync.Mutex
	results []FeedResult         // what each feed did in the round under way (SyncAll)
	starts  map[string]time.Time // when each feed's step began in this round (begin)
	began   int                  // how many feeds this round began (begin)
}

// NewFeedSyncer creates a new FeedSyncer backed by a system-privileged connection pool.
func NewFeedSyncer(pool *pgxpool.Pool) *FeedSyncer {
	return &FeedSyncer{pool: pool}
}

// SyncKEV ingests the official CISA KEV JSON catalog into global vulnerability table (D19).
func (s *FeedSyncer) SyncKEV(ctx context.Context, r io.Reader) (int, error) {
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
		s.recordFeedError(ctx, "cisa_kev", err)
		return 0, fmt.Errorf("enrich: failed to parse KEV JSON: %w", err)
	}

	const batchSize = 1000
	count := 0
	vulns := catalog.Vulnerabilities

	for i := 0; i < len(vulns); i += batchSize {
		end := i + batchSize
		if end > len(vulns) {
			end = len(vulns)
		}
		chunk := vulns[i:end]

		batch := &pgx.Batch{}
		for _, v := range chunk {
			cve := strings.ToUpper(strings.TrimSpace(v.CveID))
			if cve == "" {
				continue
			}

			var dateAdded *time.Time
			if v.DateAdded != "" {
				if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
					dateAdded = &t
				}
			}

			var dueDate *time.Time
			if v.DueDate != "" {
				if t, err := time.Parse("2006-01-02", v.DueDate); err == nil {
					dueDate = &t
				}
			}

			ransomware := strings.EqualFold(v.KnownRansomwareCampaignUse, "known")

			batch.Queue(`
				INSERT INTO vulnerability (
					id, summary, description, kev_date_added, kev_due_date, kev_ransomware, updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, NOW())
				ON CONFLICT (id) DO UPDATE SET
					kev_date_added = EXCLUDED.kev_date_added,
					kev_due_date = EXCLUDED.kev_due_date,
					kev_ransomware = EXCLUDED.kev_ransomware,
					summary = COALESCE(vulnerability.summary, EXCLUDED.summary),
					description = COALESCE(vulnerability.description, EXCLUDED.description),
					updated_at = NOW()
			`, cve, v.VulnerabilityName, v.ShortDescription, dateAdded, dueDate, ransomware)
		}

		br := s.pool.SendBatch(ctx, batch)
		for j := 0; j < batch.Len(); j++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				s.recordFeedError(ctx, "cisa_kev", err)
				return count, fmt.Errorf("enrich: executing KEV batch: %w", err)
			}
			count++
		}
		if err := br.Close(); err != nil {
			s.recordFeedError(ctx, "cisa_kev", err)
			return count, fmt.Errorf("enrich: closing KEV batch: %w", err)
		}
	}

	if err := s.recordFeedSuccess(ctx, "cisa_kev", int64(count)); err != nil {
		return count, err
	}

	return count, nil
}

// SyncEPSS ingests FIRST EPSS CSV scores (cve, epss, percentile) into global vulnerability table (D19).
//
// The file's first line names the day the scores are for: `#model_version:v2025.03.14,score_date:2025-11-17T12:55:00Z`.
// That day is stored as epss_date, not the day of the sync: a file that FIRST has not refreshed must not read as new.
// A date passed in wins; a file without the line is dated by the sync.
func (s *FeedSyncer) SyncEPSS(ctx context.Context, r io.Reader, epssDate ...time.Time) (int, error) {
	br := bufio.NewReader(r)
	date := time.Now().UTC()
	if first, err := br.Peek(1); err == nil && first[0] == '#' {
		line, _ := br.ReadString('\n')
		if d, ok := epssScoreDate(line); ok {
			date = d
		}
	}
	if len(epssDate) > 0 && !epssDate[0].IsZero() {
		date = epssDate[0]
	}
	reader := csv.NewReader(br)
	reader.Comment = '#'

	const batchSize = 5000
	count := 0

	for {
		batch := &pgx.Batch{}
		batchCount := 0

		for batchCount < batchSize {
			record, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				s.recordFeedError(ctx, "first_epss", err)
				return count, fmt.Errorf("enrich: epss csv error: %w", err)
			}
			if len(record) < 3 {
				continue
			}

			cve := strings.ToUpper(strings.TrimSpace(record[0]))
			if strings.EqualFold(cve, "cve") || cve == "" {
				continue
			}

			epssScore, err1 := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
			percentile, err2 := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
			if err1 != nil || err2 != nil {
				continue
			}

			batch.Queue(`
				INSERT INTO vulnerability (
					id, epss_score, epss_percentile, epss_date, updated_at
				) VALUES ($1, $2, $3, $4, NOW())
				ON CONFLICT (id) DO UPDATE SET
					epss_score = EXCLUDED.epss_score,
					epss_percentile = EXCLUDED.epss_percentile,
					epss_date = EXCLUDED.epss_date,
					updated_at = NOW()
			`, cve, epssScore, percentile, date)
			batchCount++
		}

		if batchCount == 0 {
			break
		}

		br := s.pool.SendBatch(ctx, batch)
		for j := 0; j < batch.Len(); j++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				s.recordFeedError(ctx, "first_epss", err)
				return count, fmt.Errorf("enrich: executing EPSS batch: %w", err)
			}
			count++
		}
		if err := br.Close(); err != nil {
			s.recordFeedError(ctx, "first_epss", err)
			return count, fmt.Errorf("enrich: closing EPSS batch: %w", err)
		}
	}

	if err := s.recordFeedSuccess(ctx, "first_epss", int64(count)); err != nil {
		return count, err
	}

	return count, nil
}

// epssScoreDate reads score_date from the comment line of an EPSS file.
func epssScoreDate(line string) (time.Time, bool) {
	const key = "score_date:"
	i := strings.Index(line, key)
	if i < 0 {
		return time.Time{}, false
	}
	v := strings.TrimSpace(line[i+len(key):])
	if j := strings.IndexAny(v, ", \t\r\n"); j >= 0 {
		v = v[:j]
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// SyncOSV ingests OSV JSON records into global vulnerability and vulnerability_alias tables (D19).
func (s *FeedSyncer) SyncOSV(ctx context.Context, r io.Reader) (int, error) {
	buffered := bufio.NewReader(r)

	// Peek at the first non-whitespace byte to check if it's an array or newline-delimited objects
	var firstByte byte
	for {
		b, err := buffered.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, nil
			}
			return 0, err
		}
		if b > ' ' { // not whitespace
			firstByte = b
			if err := buffered.UnreadByte(); err != nil {
				return 0, err
			}
			break
		}
	}

	var records []OSVRecord
	if firstByte == '[' {
		// JSON Array
		if err := json.NewDecoder(buffered).Decode(&records); err != nil {
			s.recordFeedError(ctx, "osv", err)
			return 0, fmt.Errorf("enrich: parsing OSV array: %w", err)
		}
	} else {
		// Newline-delimited JSON or single JSON object
		dec := json.NewDecoder(buffered)
		for dec.More() {
			var rec OSVRecord
			if err := dec.Decode(&rec); err != nil {
				s.recordFeedError(ctx, "osv", err)
				return 0, fmt.Errorf("enrich: parsing OSV stream: %w", err)
			}
			records = append(records, rec)
		}
	}

	count := 0
	const batchSize = 1000
	for i := 0; i < len(records); i += batchSize {
		chunk := records[i:min(i+batchSize, len(records))]
		if err := s.writeOSVChunk(ctx, chunk, osvWrite{source: SourceOSV}); err != nil {
			s.recordFeedError(ctx, "osv", err)
			return count, err
		}
		count += len(chunk)
	}

	if err := s.recordFeedSuccess(ctx, "osv", int64(count)); err != nil {
		return count, err
	}

	return count, nil
}

// GetFeedState retrieves the current sync state of a feed.
func (s *FeedSyncer) GetFeedState(ctx context.Context, feed string) (*FeedState, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT feed, cursor, last_sync, records, status, error
		FROM feed_state WHERE feed = $1`, feed)

	var st FeedState
	err := row.Scan(&st.Feed, &st.Cursor, &st.LastSync, &st.Records, &st.Status, &st.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return &FeedState{Feed: feed, Status: "idle"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enrich: reading feed state: %w", err)
	}
	return &st, nil
}

// ListFeedStates returns the status of all tracked threat feeds.
func (s *FeedSyncer) ListFeedStates(ctx context.Context) ([]FeedState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT feed, cursor, last_sync, records, status, error
		FROM feed_state ORDER BY feed ASC`)
	if err != nil {
		return nil, fmt.Errorf("enrich: listing feed states: %w", err)
	}
	defer rows.Close()

	var states []FeedState
	for rows.Next() {
		var st FeedState
		if err := rows.Scan(&st.Feed, &st.Cursor, &st.LastSync, &st.Records, &st.Status, &st.Error); err != nil {
			return nil, err
		}
		states = append(states, st)
	}
	return states, rows.Err()
}

func (s *FeedSyncer) recordFeedSuccess(ctx context.Context, feed string, records int64) error {
	s.note(FeedResult{Feed: feed, Records: records})
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_state (feed, last_sync, records, status, error)
		VALUES ($1, NOW(), $2, 'success', NULL)
		ON CONFLICT (feed) DO UPDATE SET
			last_sync = EXCLUDED.last_sync,
			records = EXCLUDED.records,
			status = 'success',
			error = NULL`, feed, records)
	if err != nil {
		return fmt.Errorf("enrich: updating feed state success: %w", err)
	}
	return nil
}

func (s *FeedSyncer) recordFeedError(ctx context.Context, feed string, syncErr error) {
	s.note(FeedResult{Feed: feed, Err: syncErr})
	errMsg := syncErr.Error()
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO feed_state (feed, last_sync, records, status, error)
		VALUES ($1, NOW(), 0, 'error', $2)
		ON CONFLICT (feed) DO UPDATE SET
			status = 'error',
			error = EXCLUDED.error`, feed, errMsg)
}

// writeOSVChunk upserts up to a thousand OSV records, their aliases and their affected ranges in one round trip.
func (s *FeedSyncer) writeOSVChunk(ctx context.Context, chunk []OSVRecord, w osvWrite) error {
	if w.source == "" {
		w.source = SourceOSV
	}
	batch := &pgx.Batch{}
	sourceIDs := make([]string, 0, len(chunk))
	for _, rec := range chunk {
		if strings.TrimSpace(rec.ID) != "" {
			sourceIDs = append(sourceIDs, strings.TrimSpace(rec.ID))
		}
	}
	// The ranges of a record are replaced as a whole: a version that was fixed, a package that was added, an advisory
	// that was withdrawn all change the rows, and a row that is no longer true must go.
	batch.Queue(`DELETE FROM vulnerability_affected WHERE source_id = ANY($1::text[])`, sourceIDs)

	for _, rec := range chunk {
		osvID := strings.TrimSpace(rec.ID)
		if osvID == "" {
			continue
		}
		pubTime, modTime := parseTime(rec.Published), parseTime(rec.Modified)

		affected := rec.Affected
		if len(affected) == 0 {
			affected = []byte("[]")
		}
		references := rec.References
		if len(references) == 0 {
			references = []byte("[]")
		}

		// D19/D11: the canonical id is a CVE when the record has one, else the OSV id itself. The ids that mean the same
		// vulnerability (the OSV id, GHSA, PYSEC, RUSTSEC...) become aliases of it, so KEV and EPSS (keyed by CVE) land
		// on the same row as the advisory. Another CVE of the same record is a different vulnerability: it is listed on
		// the row, but never made an alias, which would merge the findings of two CVEs.
		id, aliases, registerable := canonicalVulnID(osvID, rec.Aliases)

		var payload any // full mode keeps the whole record, under the name of its feed
		if w.full && len(rec.raw) > 0 {
			payload = `{"` + w.source + `":` + string(rec.raw) + `}`
		}
		cvss, bestVector := osvCVSS(rec.Severity, "osv")
		cvssJSON, _ := json.Marshal(cvss)
		if cvss == nil {
			cvssJSON = []byte("[]")
		}
		var vector *string
		if bestVector != "" {
			vector = &bestVector
		}

		batch.Queue(`
				INSERT INTO vulnerability (
					id, aliases, summary, description, published, modified, affected, "references", cvss, cvss_best_vector,
					source_payloads, updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11::jsonb, NOW())
				ON CONFLICT (id) DO UPDATE SET
					-- several advisories (GHSA, PYSEC, GO...) name the same CVE: the row lists all their ids
					aliases = ARRAY(SELECT DISTINCT a FROM unnest(vulnerability.aliases || EXCLUDED.aliases) AS a ORDER BY a),
					summary = COALESCE(EXCLUDED.summary, vulnerability.summary),
					description = COALESCE(EXCLUDED.description, vulnerability.description),
					published = COALESCE(EXCLUDED.published, vulnerability.published),
					modified = COALESCE(EXCLUDED.modified, vulnerability.modified),
					affected = COALESCE(EXCLUDED.affected, vulnerability.affected),
					"references" = COALESCE(EXCLUDED."references", vulnerability."references"),
					-- OSV's vectors fill in only what NVD (which has the scores) has not given
					cvss = CASE WHEN jsonb_array_length(vulnerability.cvss) = 0 THEN EXCLUDED.cvss ELSE vulnerability.cvss END,
					cvss_best_vector = CASE WHEN vulnerability.cvss_best_score IS NULL AND vulnerability.cvss_best_vector IS NULL
					                        THEN EXCLUDED.cvss_best_vector ELSE vulnerability.cvss_best_vector END,
					source_payloads = CASE WHEN EXCLUDED.source_payloads IS NULL THEN vulnerability.source_payloads
					                       ELSE COALESCE(vulnerability.source_payloads, '{}'::jsonb) || EXCLUDED.source_payloads END,
					updated_at = NOW()
			`, id, aliases, rec.Summary, rec.Details, pubTime, modTime, affected, references, string(cvssJSON), vector, payload)

		for _, alias := range registerable {
			batch.Queue(`
					INSERT INTO vulnerability_alias (alias, vulnerability_id, source)
					VALUES ($1, $2, $3)
					ON CONFLICT (alias) DO UPDATE SET vulnerability_id = EXCLUDED.vulnerability_id, source = EXCLUDED.source
					WHERE vulnerability_alias.source IS NULL OR vulnerability_alias.source = EXCLUDED.source
				`, alias, id, w.source)
		}

		withdrawn := parseWithdrawn(rec.Withdrawn)
		for _, r := range affectedRows(rec.Affected) {
			batch.Queue(`
					INSERT INTO vulnerability_affected (
						vulnerability_id, source_id, ecosystem, package_name, package_name_normalised, purl_base,
						range_type, introduced, fixed, last_affected, "limit", versions, withdrawn, updated_at
					) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''), $12, $13, NOW())
				`, id, osvID, r.Ecosystem, r.Name, r.NameNormalised, r.PurlBase, r.RangeType,
				r.Introduced, r.Fixed, r.LastAffected, r.Limit, nonNilStrings(r.Versions), withdrawn)
		}
	}

	br := s.pool.SendBatch(ctx, batch)
	for j := 0; j < batch.Len(); j++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return fmt.Errorf("enrich: executing OSV batch: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("enrich: closing OSV batch: %w", err)
	}
	return nil
}

func parseTime(v string) *time.Time {
	if v == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return &t
	}
	return nil
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// canonicalVulnID picks the canonical id for an OSV record (docs/03, D11, docs/33 section 5.1).
//
// It returns the canonical id, every other identifier of the record (for vulnerability.aliases, which only lists), and
// the identifiers to register in vulnerability_alias, which makes them mean the canonical id. The canonical id is a
// CVE when the record names one; when it names several, the smallest, so the answer does not depend on the order the
// source listed them in. The other CVEs are listed but not registered: they are other vulnerabilities, and an alias
// would make the findings of two CVEs one. With no CVE the canonical id is the OSV id.
func canonicalVulnID(osvID string, aliases []string) (canon string, all, registerable []string) {
	canon = osvID
	var cves []string
	for _, a := range aliases {
		if a = strings.ToUpper(strings.TrimSpace(a)); strings.HasPrefix(a, "CVE-") {
			cves = append(cves, a)
		}
	}
	if len(cves) > 0 {
		sort.Strings(cves)
		canon = cves[0]
	}
	all, registerable = []string{}, []string{}
	seen := map[string]bool{canon: true}
	for _, a := range append([]string{osvID}, aliases...) {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] || seen[strings.ToUpper(a)] {
			continue
		}
		seen[a] = true
		all = append(all, a)
		if !strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			registerable = append(registerable, a)
		}
	}
	return canon, all, registerable
}
