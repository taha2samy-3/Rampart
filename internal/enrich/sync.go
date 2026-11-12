package enrich

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeedState records the synchronization status of an external threat intelligence feed.
type FeedState struct {
	Feed     string     `json:"feed"`
	Cursor   *string    `json:"cursor,omitempty"`
	LastSync *time.Time `json:"last_sync,omitempty"`
	Records  int64      `json:"records"`
	Status   string     `json:"status"` // idle | syncing | success | error
	Error    *string    `json:"error,omitempty"`
}

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
}

// FeedSyncer writes global intelligence tables as rampart_system (D19).
type FeedSyncer struct {
	pool *pgxpool.Pool
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
func (s *FeedSyncer) SyncEPSS(ctx context.Context, r io.Reader, epssDate ...time.Time) (int, error) {
	reader := csv.NewReader(bufio.NewReader(r))
	reader.Comment = '#'

	date := time.Now().UTC()
	if len(epssDate) > 0 && !epssDate[0].IsZero() {
		date = epssDate[0]
	}

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
		if err := s.writeOSVChunk(ctx, chunk); err != nil {
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
	errMsg := syncErr.Error()
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO feed_state (feed, last_sync, records, status, error)
		VALUES ($1, NOW(), 0, 'error', $2)
		ON CONFLICT (feed) DO UPDATE SET
			status = 'error',
			error = EXCLUDED.error`, feed, errMsg)
}

// writeOSVChunk upserts up to a thousand OSV records and their aliases in one round trip.
func (s *FeedSyncer) writeOSVChunk(ctx context.Context, chunk []OSVRecord) error {
	batch := &pgx.Batch{}
	for _, rec := range chunk {
		id := strings.TrimSpace(rec.ID)
		if id == "" {
			continue
		}

		var pubTime *time.Time
		if rec.Published != "" {
			if t, err := time.Parse(time.RFC3339, rec.Published); err == nil {
				pubTime = &t
			}
		}

		var modTime *time.Time
		if rec.Modified != "" {
			if t, err := time.Parse(time.RFC3339, rec.Modified); err == nil {
				modTime = &t
			}
		}

		affected := rec.Affected
		if len(affected) == 0 {
			affected = []byte("[]")
		}

		references := rec.References
		if len(references) == 0 {
			references = []byte("[]")
		}

		// D19/D11: the canonical id is the CVE when the record has one, else the OSV id itself. Every other
		// identifier (the OSV id, GHSA, PYSEC, RUSTSEC...) becomes an alias of it, so KEV and EPSS (keyed by
		// CVE) land on the same row as the advisory.
		id, aliases := canonicalVulnID(id, rec.Aliases)

		batch.Queue(`
				INSERT INTO vulnerability (
					id, aliases, summary, description, published, modified, affected, "references", updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
				ON CONFLICT (id) DO UPDATE SET
					aliases = CASE WHEN cardinality(EXCLUDED.aliases) > 0 THEN EXCLUDED.aliases ELSE vulnerability.aliases END,
					summary = COALESCE(EXCLUDED.summary, vulnerability.summary),
					description = COALESCE(EXCLUDED.description, vulnerability.description),
					published = COALESCE(EXCLUDED.published, vulnerability.published),
					modified = COALESCE(EXCLUDED.modified, vulnerability.modified),
					affected = COALESCE(EXCLUDED.affected, vulnerability.affected),
					"references" = COALESCE(EXCLUDED."references", vulnerability."references"),
					updated_at = NOW()
			`, id, aliases, rec.Summary, rec.Details, pubTime, modTime, affected, references)

		for _, alias := range aliases {
			aliasClean := strings.TrimSpace(alias)
			if aliasClean != "" {
				batch.Queue(`
						INSERT INTO vulnerability_alias (alias, vulnerability_id)
						VALUES ($1, $2)
						ON CONFLICT (alias) DO NOTHING
					`, aliasClean, id)
			}
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

// canonicalVulnID picks the canonical id for an OSV record and returns it with the remaining identifiers
// as aliases: prefer a CVE, else the OSV id (docs/03, D11).
func canonicalVulnID(osvID string, aliases []string) (string, []string) {
	canon := osvID
	for _, a := range aliases {
		if a = strings.TrimSpace(a); strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			canon = strings.ToUpper(a)
			break
		}
	}
	out := []string{}
	seen := map[string]bool{canon: true}
	for _, a := range append([]string{osvID}, aliases...) {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return canon, out
}
