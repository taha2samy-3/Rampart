package store

import (
	"context"
	"sort"
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

// The ledger reads each finding's life as a sequence of closings and returns, not from the finding as it is now: a
// finding closed on 1 Oct and reopened on 10 Oct was closed on 5 Oct, and the current row (resolved_at is cleared on
// reopening) cannot say so. The transitions come from the finding's events (closed by a rescan, a state change, a risk
// acceptance approved, expired or revoked, a reactivation) and from resolved_at for a finding that has none (D125).
//
// They are read once, in order, and replayed in memory: a closing counts only when the finding was open and a return
// only when it was closed (a move from fixed to risk_accepted is not a second closing, and open to under_investigation
// is not a return); an event that is a return by its nature (a reactivation, an acceptance that ended) counts as one
// even when the closing before it was not recorded (a finding older than its events). The same query in SQL, with a
// correlated lookup per finding, took a minute on 10,000 findings; the replay is linear in the transitions.
type transition struct {
	id    uuid.UUID
	at    time.Time
	kind  string // close | open
	ret   bool
	first time.Time // the finding's first_seen
}

func loadTransitions(ctx context.Context, tx pgx.Tx, tenantID, appID uuid.UUID) ([]transition, error) {
	rows, err := tx.Query(ctx, `
		SELECT raw.finding_id, raw.at, raw.kind, raw.ret, f.first_seen FROM (
			SELECT e.finding_id, e.at,
			       CASE WHEN e.type IN ('closed_by_rescan', 'risk_acceptance_approved') THEN 'close'
			            WHEN e.type IN ('reactivated', 'risk_acceptance_expired', 'risk_acceptance_revoked') THEN 'open'
			            WHEN e.type = 'state_changed' AND (e."to" #>> '{}') IN ('open', 'under_investigation', 'affected') THEN 'open'
			            WHEN e.type = 'state_changed' AND (e."to" #>> '{}') IN ('fixed', 'not_affected', 'risk_accepted', 'out_of_scope', 'duplicate') THEN 'close'
			       END AS kind,
			       e.type IN ('reactivated', 'risk_acceptance_expired', 'risk_acceptance_revoked') AS ret
			FROM finding_event e JOIN finding f ON f.id = e.finding_id AND f.tenant_id = e.tenant_id
			WHERE e.tenant_id = $1 AND f.application_id = $2
			UNION ALL
			SELECT f.id, f.resolved_at, 'close', false FROM finding f WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.resolved_at IS NOT NULL
		) raw JOIN finding f ON f.id = raw.finding_id AND f.tenant_id = $1
		WHERE raw.kind IS NOT NULL
		ORDER BY raw.finding_id, raw.at, raw.kind DESC`, tenantID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []transition
	for rows.Next() {
		var t transition
		if err := rows.Scan(&t.id, &t.at, &t.kind, &t.ret, &t.first); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// replay is what the transitions say about a range [from, to) and the one before it.
type replay struct {
	closedIn, reopenedIn map[uuid.UUID]time.Time // finding -> its latest closing / return in the range
	closedPrev           int                     // findings closed in the range before
	closedAtStart        int                     // findings seen before from whose last transition before it was a closing
	closedAtEnd          []uuid.UUID             // the same at to
	closedDays           map[string]int          // day (UTC) -> findings closed that day
}

func replayTransitions(ts []transition, from, to, prev time.Time) replay {
	r := replay{closedIn: map[uuid.UUID]time.Time{}, reopenedIn: map[uuid.UUID]time.Time{}, closedDays: map[string]int{}}
	closedPrev := map[uuid.UUID]bool{}
	for i := 0; i < len(ts); {
		j := i
		for j < len(ts) && ts[j].id == ts[i].id {
			j++
		}
		id, first := ts[i].id, ts[i].first
		last, atStart, atEnd := "open", "open", "open" // the kind before each transition, and the state at from and at to
		daySeen := map[string]bool{}
		for _, t := range ts[i:j] {
			closing := t.kind == "close" && last == "open"
			returning := t.kind == "open" && (last == "close" || t.ret)
			if closing {
				switch {
				case !t.at.Before(from) && t.at.Before(to):
					if t.at.After(r.closedIn[id]) {
						r.closedIn[id] = t.at
					}
					if d := t.at.UTC().Format("2006-01-02"); !daySeen[d] {
						daySeen[d] = true
						r.closedDays[d]++
					}
				case !t.at.Before(prev) && t.at.Before(from):
					closedPrev[id] = true
				}
			}
			if returning && !t.at.Before(from) && t.at.Before(to) && t.at.After(r.reopenedIn[id]) {
				r.reopenedIn[id] = t.at
			}
			if t.at.Before(from) {
				atStart = t.kind
			}
			if t.at.Before(to) {
				atEnd = t.kind
			}
			last = t.kind
		}
		if first.Before(from) && atStart == "close" {
			r.closedAtStart++
		}
		if first.Before(to) && atEnd == "close" {
			r.closedAtEnd = append(r.closedAtEnd, id)
		}
		i = j
	}
	r.closedPrev = len(closedPrev)
	return r
}

// newestFirst returns the findings of m, the latest transition first, cut at ChangeLimit+1 (one more says there is more).
func newestFirst(m map[uuid.UUID]time.Time) ([]uuid.UUID, []time.Time) {
	ids := make([]uuid.UUID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool {
		if !m[ids[a]].Equal(m[ids[b]]) {
			return m[ids[a]].After(m[ids[b]])
		}
		return ids[a].String() < ids[b].String()
	})
	if len(ids) > ChangeLimit+1 {
		ids = ids[:ChangeLimit+1]
	}
	times := make([]time.Time, len(ids))
	for i, id := range ids {
		times[i] = m[id]
	}
	return ids, times
}

// ApplicationChanges answers, for an application: which findings appeared in the range, which were closed, which came
// back, and which were open at its end, with the exact counts and the same counts for the range before it. A finding
// counts as open at an instant when it had been seen by then and its last transition by then was not a closing. A
// finding closed in the range and reopened in it is in all of new, closed and reopened; the counts are of findings, so
// a finding that cycles twice in the range is still one.
func (s *PostgresStore) ApplicationChanges(ctx context.Context, tenantID, appID uuid.UUID, from, to time.Time) (*ApplicationChanges, error) {
	span := to.Sub(from)
	prev := from.Add(-span)
	out := &ApplicationChanges{From: from, To: to, New: []FindingChange{}, Closed: []FindingChange{}, Reopened: []FindingChange{}, OpenAtEnd: []FindingChange{}, Days: []ChangeDay{}}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var seenAtStart, seenAtEnd int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE first_seen >= $3 AND first_seen < $4),
			       count(*) FILTER (WHERE first_seen >= $5 AND first_seen < $3),
			       count(*) FILTER (WHERE first_seen < $3),
			       count(*) FILTER (WHERE first_seen < $4)
			FROM finding WHERE tenant_id = $1 AND application_id = $2`, tenantID, appID, from, to, prev).Scan(
			&out.Counts.New, &out.Previous.New, &seenAtStart, &seenAtEnd); err != nil {
			return err
		}
		ts, err := loadTransitions(ctx, tx, tenantID, appID)
		if err != nil {
			return err
		}
		rp := replayTransitions(ts, from, to, prev)
		out.Counts.Closed, out.Previous.Closed, out.Counts.Reopened = len(rp.closedIn), rp.closedPrev, len(rp.reopenedIn)
		out.Counts.OpenAtStart = seenAtStart - rp.closedAtStart
		out.Counts.OpenAtEnd = seenAtEnd - len(rp.closedAtEnd)

		// Day by day, for the chart.
		days := map[string]*ChangeDay{}
		for d := from; d.Before(to); d = d.AddDate(0, 0, 1) {
			k := d.UTC().Format("2006-01-02")
			days[k] = &ChangeDay{Day: k}
			out.Days = append(out.Days, ChangeDay{Day: k})
		}
		rows, err := tx.Query(ctx, `SELECT to_char(date_trunc('day', first_seen AT TIME ZONE 'UTC'), 'YYYY-MM-DD'), count(*) FROM finding
			WHERE tenant_id = $1 AND application_id = $2 AND first_seen >= $3 AND first_seen < $4 GROUP BY 1`, tenantID, appID, from, to)
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
				d.New = n
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for day, n := range rp.closedDays {
			if d := days[day]; d != nil {
				d.Closed = n
			}
		}
		for i := range out.Days {
			if d := days[out.Days[i].Day]; d != nil {
				out.Days[i] = *d
			}
		}

		const cols = `f.id, COALESCE(f.vulnerability_id, ''), f.rule_id, f.title, f.category, f.severity, f.risk_band, f.risk_score, f.state,
		              COALESCE(f.resolution, ''), COALESCE(NULLIF(a.display_name, ''), a.key), f.first_seen, f.resolved_at`
		list := func(query string, args ...any) ([]FindingChange, bool, error) {
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
		// The findings of a transition list, with the time of the transition, newest first.
		byTime := func(m map[uuid.UUID]time.Time) ([]FindingChange, bool, error) {
			ids, times := newestFirst(m)
			if len(ids) == 0 {
				return []FindingChange{}, false, nil
			}
			return list(`SELECT `+cols+`, t.at FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
				JOIN unnest($3::uuid[], $4::timestamptz[]) AS t(id, at) ON t.id = f.id
				WHERE f.tenant_id = $1 AND f.application_id = $2 ORDER BY t.at DESC, f.id`, tenantID, appID, ids, times)
		}
		if out.New, out.NewMore, err = list(`SELECT `+cols+`, f.first_seen FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.first_seen >= $3 AND f.first_seen < $4
			ORDER BY f.risk_score DESC, f.first_seen DESC LIMIT `+itoa(ChangeLimit+1), tenantID, appID, from, to); err != nil {
			return err
		}
		if out.Closed, out.ClosedMore, err = byTime(rp.closedIn); err != nil {
			return err
		}
		if out.Reopened, out.ReopenedMore, err = byTime(rp.reopenedIn); err != nil {
			return err
		}
		closedAtEnd := rp.closedAtEnd
		if closedAtEnd == nil {
			closedAtEnd = []uuid.UUID{}
		}
		out.OpenAtEnd, out.OpenMore, err = list(`SELECT `+cols+`, f.first_seen FROM finding f JOIN asset a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
			WHERE f.tenant_id = $1 AND f.application_id = $2 AND f.first_seen < $3 AND f.id <> ALL($4::uuid[])
			ORDER BY f.risk_score DESC, f.first_seen LIMIT `+itoa(ChangeLimit+1), tenantID, appID, to, closedAtEnd)
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
