package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChangeLimit bounds each list of an application's changes; the summary counts are exact beyond it.
const ChangeLimit = 1000

// FindingChange is a finding in one list of an application's changes: when it came, when it went, and what it is.
type FindingChange struct {
	ID              uuid.UUID  `json:"id"`
	VulnerabilityID string     `json:"vulnerability_id,omitempty"`
	RuleID          string     `json:"rule_id"`
	Title           string     `json:"title"`
	Category        string     `json:"category"`
	Severity        string     `json:"severity"`
	RiskBand        string     `json:"risk_band"`
	RiskScore       int        `json:"risk_score"`
	State           string     `json:"state"`
	Resolution      string     `json:"resolution,omitempty"` // how it was closed: fixed, not_affected, risk_accepted, duplicate...
	Asset           string     `json:"asset"`
	FirstSeen       time.Time  `json:"first_seen"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	At              time.Time  `json:"at"` // the time that put it in this list: first seen, closed or reopened
}

// ChangeDay is one day of the range: findings that came and findings that were closed.
type ChangeDay struct {
	Day    string `json:"day"` // YYYY-MM-DD, UTC
	New    int    `json:"new"`
	Closed int    `json:"closed"`
}

// ChangeCounts are the exact counts of a range, and of the range of the same length before it.
type ChangeCounts struct {
	New         int `json:"new"`
	Closed      int `json:"closed"`
	Reopened    int `json:"reopened"`
	OpenAtStart int `json:"open_at_start"`
	OpenAtEnd   int `json:"open_at_end"`
}

// ApplicationChanges is what changed in an application between two instants (a half-open range [From, To)).
type ApplicationChanges struct {
	From, To     time.Time
	Counts       ChangeCounts
	Previous     ChangeCounts // the range of the same length that ends where this one starts (Reopened and the open counts are not read for it)
	Days         []ChangeDay
	New          []FindingChange
	Closed       []FindingChange
	Reopened     []FindingChange
	OpenAtEnd    []FindingChange // the findings that were open when the range ended, worst first
	NewMore      bool
	ClosedMore   bool
	ReopenedMore bool
	OpenMore     bool
}

// ChangeReader reads what changed in an application. Only the PostgreSQL store implements it.
type ChangeReader interface {
	ApplicationChanges(ctx context.Context, tenantID, appID uuid.UUID, from, to time.Time) (*ApplicationChanges, error)
}

// ApplicationChanges answers, for an application: which findings appeared in the range, which were closed, which came
// back, and which were open at its end, with the exact counts and the same counts for the range before it. A finding
// counts as open at an instant when it had been seen by then and was not closed by then; a finding that was closed and
// reopened has lost its first closing (resolved_at is cleared on reopening), so the open counts are read from the
// finding as it is now, and the reopened list (from the finding's events) is how a return is seen.
func (s *PostgresStore) ApplicationChanges(ctx context.Context, tenantID, appID uuid.UUID, from, to time.Time) (*ApplicationChanges, error) {
	span := to.Sub(from)
	prev := from.Add(-span)
	out := &ApplicationChanges{From: from, To: to, New: []FindingChange{}, Closed: []FindingChange{}, Reopened: []FindingChange{}, OpenAtEnd: []FindingChange{}, Days: []ChangeDay{}}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		// The exact counts, this range and the one before it.
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE first_seen >= $3 AND first_seen < $4),
			       count(*) FILTER (WHERE resolved_at >= $3 AND resolved_at < $4),
			       count(*) FILTER (WHERE first_seen >= $5 AND first_seen < $3),
			       count(*) FILTER (WHERE resolved_at >= $5 AND resolved_at < $3),
			       count(*) FILTER (WHERE first_seen < $3 AND (resolved_at IS NULL OR resolved_at >= $3)),
			       count(*) FILTER (WHERE first_seen < $4 AND (resolved_at IS NULL OR resolved_at >= $4))
			FROM finding WHERE tenant_id = $1 AND application_id = $2`, tenantID, appID, from, to, prev).Scan(
			&out.Counts.New, &out.Counts.Closed, &out.Previous.New, &out.Previous.Closed, &out.Counts.OpenAtStart, &out.Counts.OpenAtEnd); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT count(DISTINCT e.finding_id) FROM finding_event e JOIN finding f ON f.id = e.finding_id AND f.tenant_id = e.tenant_id
			WHERE e.tenant_id = $1 AND f.application_id = $2 AND e.type = 'reactivated' AND e.at >= $3 AND e.at < $4`,
			tenantID, appID, from, to).Scan(&out.Counts.Reopened); err != nil {
			return err
		}

		// Day by day, for the chart.
		days := map[string]*ChangeDay{}
		for d := from; d.Before(to); d = d.AddDate(0, 0, 1) {
			k := d.UTC().Format("2006-01-02")
			days[k] = &ChangeDay{Day: k}
			out.Days = append(out.Days, ChangeDay{Day: k})
		}
		for _, q := range []struct {
			col  string
			into func(*ChangeDay, int)
		}{{"first_seen", func(d *ChangeDay, n int) { d.New = n }}, {"resolved_at", func(d *ChangeDay, n int) { d.Closed = n }}} {
			rows, err := tx.Query(ctx, `SELECT to_char(date_trunc('day', `+q.col+` AT TIME ZONE 'UTC'), 'YYYY-MM-DD'), count(*) FROM finding
				WHERE tenant_id = $1 AND application_id = $2 AND `+q.col+` >= $3 AND `+q.col+` < $4 GROUP BY 1`, tenantID, appID, from, to)
			if err != nil {
				return err
			}
			for rows.Next() {
				var day string
				var n int
				if err := rows.Scan(&day, &n); err != nil {
					rows.Close()
					return err
				}
				if d := days[day]; d != nil {
					q.into(d, n)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		for i := range out.Days {
			if d := days[out.Days[i].Day]; d != nil {
				out.Days[i] = *d
			}
		}

		const cols = `f.id, COALESCE(f.vulnerability_id, ''), f.rule_id, f.title, f.category, f.severity, f.risk_band, f.risk_score, f.state,
		              COALESCE(f.resolution, ''), COALESCE(NULLIF(a.display_name, ''), a.key), f.first_seen, f.resolved_at`
		list := func(query string, at func(*FindingChange), args ...any) ([]FindingChange, bool, error) {
			rows, err := tx.Query(ctx, query, args...)
			if err != nil {
				return nil, false, err
			}
			defer rows.Close()
			var res []FindingChange
			for rows.Next() {
				var c FindingChange
				var evAt *time.Time
				if err := rows.Scan(&c.ID, &c.VulnerabilityID, &c.RuleID, &c.Title, &c.Category, &c.Severity, &c.RiskBand, &c.RiskScore, &c.State,
					&c.Resolution, &c.Asset, &c.FirstSeen, &c.ResolvedAt, &evAt); err != nil {
					return nil, false, err
				}
				if evAt != nil {
					c.At = *evAt
				}
				at(&c)
				res = append(res, c)
			}
			more := len(res) > ChangeLimit
			if more {
				res = res[:ChangeLimit]
			}
			if res == nil {
				res = []FindingChange{}
			}
			return res, more, rows.Err()
		}
		var err error
		if out.New, out.NewMore, err = list(`SELECT `+cols+`, f.first_seen FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.first_seen >= $3 AND f.first_seen < $4
			ORDER BY f.risk_score DESC, f.first_seen DESC LIMIT `+itoa(ChangeLimit+1), func(c *FindingChange) {}, tenantID, appID, from, to); err != nil {
			return err
		}
		if out.Closed, out.ClosedMore, err = list(`SELECT `+cols+`, f.resolved_at FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.resolved_at >= $3 AND f.resolved_at < $4
			ORDER BY f.resolved_at DESC LIMIT `+itoa(ChangeLimit+1), func(c *FindingChange) {}, tenantID, appID, from, to); err != nil {
			return err
		}
		if out.Reopened, out.ReopenedMore, err = list(`SELECT DISTINCT ON (f.id) `+cols+`, e.at FROM finding_event e JOIN finding f ON f.id = e.finding_id AND f.tenant_id = e.tenant_id
			JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE e.tenant_id = $1 AND f.application_id = $2 AND e.type = 'reactivated' AND e.at >= $3 AND e.at < $4
			ORDER BY f.id, e.at DESC LIMIT `+itoa(ChangeLimit+1), func(c *FindingChange) {}, tenantID, appID, from, to); err != nil {
			return err
		}
		out.OpenAtEnd, out.OpenMore, err = list(`SELECT `+cols+`, f.first_seen FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.first_seen < $3 AND (f.resolved_at IS NULL OR f.resolved_at >= $3)
			ORDER BY f.risk_score DESC, f.first_seen LIMIT `+itoa(ChangeLimit+1), func(c *FindingChange) {}, tenantID, appID, to)
		return err
	})
	return out, err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
