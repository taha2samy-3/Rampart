package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RuleMatch is a scanner's own rule a control names. RuleID may end in * to take every rule with that prefix.
type RuleMatch struct {
	ScannerFamily string `json:"f"`
	RuleID        string `json:"p"`
}

// ControlMatch is what a control looks for in findings (docs/16 D52, D102).
type ControlMatch struct {
	ID          string
	CWEs        []int
	Categories  []string
	Rules       []RuleMatch
	MinSeverity string // a risk band; empty for every band
}

// ControlCount is what bears on one control: the open findings by risk band, and the accepted ones apart. An
// accepted finding is an exception someone approved: it does not make the control open, and an auditor must see it.
type ControlCount struct {
	Open     map[string]int
	Accepted int
}

// ScanEvidence is the last completed scan of one scanner family for one application.
type ScanEvidence struct {
	App    uuid.UUID
	Family string
	At     time.Time
}

// Attestation is a person's reading of a control no scan can read (D102).
type Attestation struct {
	ID            uuid.UUID  `json:"id"`
	FrameworkID   string     `json:"framework_id"`
	ControlID     string     `json:"control_id"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	Status        string     `json:"status"` // passed | failed
	Note          string     `json:"note"`
	EvidenceURL   string     `json:"evidence_url,omitempty"`
	AttestedBy    string     `json:"attested_by"`
	AttestedAt    time.Time  `json:"attested_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

// ErrNoSnapshot is returned when no reading was kept for that day.
var ErrNoSnapshot = errors.New("store: no compliance reading kept for that day")

// ComplianceReader answers the Compliance screen. Only the PostgreSQL store implements it (docs/16 D52).
type ComplianceReader interface {
	// ControlCounts returns, per control id, the findings that bear on it. apps narrows to those applications; nil
	// reads every application of the tenant.
	ControlCounts(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, controls []ControlMatch) (map[string]ControlCount, error)
	// RecentScans returns each application's scanner families with their last completed run since `since`.
	RecentScans(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, since time.Time) ([]ScanEvidence, error)
	// FamilyFindingCategories says what each scanner family produced in the tenant: family -> categories.
	FamilyFindingCategories(ctx context.Context, tenantID uuid.UUID) (map[string][]string, error)
	// Attestations returns the attestations of a framework, newest first.
	Attestations(ctx context.Context, tenantID uuid.UUID, frameworkID string) ([]Attestation, error)
	// AddAttestation records one; attestations are never changed or removed.
	AddAttestation(ctx context.Context, tenantID uuid.UUID, a Attestation) error
	// SaveComplianceSnapshot keeps the day's reading of a framework; a second one the same day replaces it.
	SaveComplianceSnapshot(ctx context.Context, tenantID uuid.UUID, frameworkID string, day time.Time, reading []byte) error
	// ComplianceSnapshot returns the reading kept for that day, or ErrNoSnapshot.
	ComplianceSnapshot(ctx context.Context, tenantID uuid.UUID, frameworkID string, day time.Time) ([]byte, error)
	// ComplianceSnapshotDays lists the days a reading was kept for, newest first.
	ComplianceSnapshotDays(ctx context.Context, tenantID uuid.UUID, frameworkID string, limit int) ([]time.Time, error)
}

func bandRank(b string) int {
	switch b {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// controlBreaksSQL is the condition under which a finding f counts against a control c (the CTE of ControlCounts and
// ControlDeadlines). compliance.Control.Breaks is the same rule for one finding in Go, and a test holds them together.
const controlBreaksSQL = `((cardinality(c.cwes) > 0 AND f.cwes && c.cwes) OR f.category = ANY(c.cats)
			      OR EXISTS (SELECT 1 FROM jsonb_array_elements(c.rules) r
			                 WHERE f.rule_scanner_family = r->>'f'
			                   AND (f.rule_id = r->>'p' OR ((r->>'w')::boolean AND starts_with(f.rule_id, r->>'p')))))
			 AND (CASE coalesce(f.risk_band, 'low') WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) >= c.min`

func (s *PostgresStore) ControlCounts(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, controls []ControlMatch) (map[string]ControlCount, error) {
	out := map[string]ControlCount{}
	type row struct {
		ID    string           `json:"id"`
		CWEs  []int            `json:"cwes"`
		Cats  []string         `json:"cats"`
		Rules []map[string]any `json:"rules"`
		Min   int              `json:"min"`
	}
	body := make([]row, 0, len(controls))
	for _, c := range controls {
		out[c.ID] = ControlCount{Open: map[string]int{}}
		r := row{ID: c.ID, CWEs: c.CWEs, Cats: c.Categories, Rules: []map[string]any{}, Min: bandRank(c.MinSeverity)}
		if r.CWEs == nil {
			r.CWEs = []int{}
		}
		if r.Cats == nil {
			r.Cats = []string{}
		}
		for _, m := range c.Rules {
			prefix, wild := strings.CutSuffix(m.RuleID, "*")
			r.Rules = append(r.Rules, map[string]any{"f": m.ScannerFamily, "p": prefix, "w": wild})
		}
		body = append(body, r)
	}
	raw, _ := json.Marshal(body)
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH c AS (SELECT * FROM jsonb_to_recordset($2::jsonb) AS x(id text, cwes int[], cats text[], rules jsonb, min int))
			SELECT c.id, coalesce(f.risk_band, 'low'), f.state = 'risk_accepted', count(*)
			FROM c JOIN finding f ON f.tenant_id = $1
			 AND (f.state IN `+activeStates+` OR f.state = 'risk_accepted')
			 AND ($3::uuid[] IS NULL OR f.application_id = ANY($3))
			 AND `+controlBreaksSQL+`
			GROUP BY 1, 2, 3`, tenantID, raw, apps)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, band string
			var accepted bool
			var n int
			if err := rows.Scan(&id, &band, &accepted, &n); err != nil {
				return err
			}
			cc := out[id]
			if accepted {
				cc.Accepted += n
			} else {
				cc.Open[band] += n
			}
			out[id] = cc
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) RecentScans(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, since time.Time) ([]ScanEvidence, error) {
	var out []ScanEvidence
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT r.application_id, sc.scanner_family, max(r.created_at)
			FROM ingest_run_scope sc JOIN ingest_run r ON r.id = sc.ingest_run_id AND r.tenant_id = sc.tenant_id
			WHERE r.tenant_id = $1 AND r.status IN ('completed', 'completed_with_errors') AND r.created_at >= $2
			  AND r.application_id IS NOT NULL AND ($3::uuid[] IS NULL OR r.application_id = ANY($3))
			GROUP BY r.application_id, sc.scanner_family`, tenantID, since, apps)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e ScanEvidence
			if err := rows.Scan(&e.App, &e.Family, &e.At); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) FamilyFindingCategories(ctx context.Context, tenantID uuid.UUID) (map[string][]string, error) {
	out := map[string][]string{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT rule_scanner_family, array_agg(DISTINCT category) FROM finding WHERE tenant_id = $1 GROUP BY 1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fam string
			var cats []string
			if err := rows.Scan(&fam, &cats); err != nil {
				return err
			}
			out[fam] = cats
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) Attestations(ctx context.Context, tenantID uuid.UUID, frameworkID string) ([]Attestation, error) {
	var out []Attestation
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, framework_id, control_id, application_id, status, note, evidence_url, attested_by, attested_at, expires_at
			FROM compliance_attestation WHERE tenant_id = $1 AND framework_id = $2 ORDER BY attested_at DESC, id`, tenantID, frameworkID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Attestation
			if err := rows.Scan(&a.ID, &a.FrameworkID, &a.ControlID, &a.ApplicationID, &a.Status, &a.Note, &a.EvidenceURL, &a.AttestedBy, &a.AttestedAt, &a.ExpiresAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) AddAttestation(ctx context.Context, tenantID uuid.UUID, a Attestation) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO compliance_attestation
			(id, tenant_id, framework_id, control_id, application_id, status, note, evidence_url, attested_by, attested_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			a.ID, tenantID, a.FrameworkID, a.ControlID, a.ApplicationID, a.Status, a.Note, a.EvidenceURL, a.AttestedBy, a.AttestedAt, a.ExpiresAt)
		return err
	})
}

func (s *PostgresStore) SaveComplianceSnapshot(ctx context.Context, tenantID uuid.UUID, frameworkID string, day time.Time, reading []byte) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO compliance_snapshot (tenant_id, framework_id, day, reading, taken_at) VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (tenant_id, framework_id, day) DO UPDATE SET reading = EXCLUDED.reading, taken_at = NOW()`,
			tenantID, frameworkID, day.UTC().Format("2006-01-02"), reading)
		return err
	})
}

func (s *PostgresStore) ComplianceSnapshot(ctx context.Context, tenantID uuid.UUID, frameworkID string, day time.Time) ([]byte, error) {
	var out []byte
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT reading FROM compliance_snapshot WHERE tenant_id = $1 AND framework_id = $2 AND day = $3`,
			tenantID, frameworkID, day.UTC().Format("2006-01-02")).Scan(&out)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSnapshot
		}
		return err
	})
	return out, err
}

func (s *PostgresStore) ComplianceSnapshotDays(ctx context.Context, tenantID uuid.UUID, frameworkID string, limit int) ([]time.Time, error) {
	var out []time.Time
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT day FROM compliance_snapshot WHERE tenant_id = $1 AND framework_id = $2 ORDER BY day DESC LIMIT $3`,
			tenantID, frameworkID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d time.Time
			if err := rows.Scan(&d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// ControlDeadline is the time left on the open findings that break one control.
type ControlDeadline struct {
	Open     int        // open findings that break it
	Overdue  int        // of them, past their SLA due date
	Earliest *time.Time // the soonest SLA due date among them (nil when none has one)
}

// ComplianceDeadlines tells, for each control, how soon the findings that break it fall due, so a person can fix them
// before the control is out of compliance by deadline and not only by count. Only the PostgreSQL store implements it.
type ComplianceDeadlines interface {
	ControlDeadlines(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, controls []ControlMatch) (map[string]ControlDeadline, error)
}

// ControlDeadlines reads the open (not accepted) findings that break each control, with their soonest SLA due date.
func (s *PostgresStore) ControlDeadlines(ctx context.Context, tenantID uuid.UUID, apps []uuid.UUID, controls []ControlMatch) (map[string]ControlDeadline, error) {
	out := map[string]ControlDeadline{}
	type row struct {
		ID    string           `json:"id"`
		CWEs  []int            `json:"cwes"`
		Cats  []string         `json:"cats"`
		Rules []map[string]any `json:"rules"`
		Min   int              `json:"min"`
	}
	body := make([]row, 0, len(controls))
	for _, c := range controls {
		r := row{ID: c.ID, CWEs: c.CWEs, Cats: c.Categories, Rules: []map[string]any{}, Min: bandRank(c.MinSeverity)}
		if r.CWEs == nil {
			r.CWEs = []int{}
		}
		if r.Cats == nil {
			r.Cats = []string{}
		}
		for _, m := range c.Rules {
			prefix, wild := strings.CutSuffix(m.RuleID, "*")
			r.Rules = append(r.Rules, map[string]any{"f": m.ScannerFamily, "p": prefix, "w": wild})
		}
		body = append(body, r)
	}
	raw, _ := json.Marshal(body)
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH c AS (SELECT * FROM jsonb_to_recordset($2::jsonb) AS x(id text, cwes int[], cats text[], rules jsonb, min int))
			SELECT c.id, count(DISTINCT f.id), count(DISTINCT f.id) FILTER (WHERE f.sla_due_date IS NOT NULL AND f.sla_due_date < NOW()), min(f.sla_due_date)
			FROM c JOIN finding f ON f.tenant_id = $1
			 AND f.state IN `+activeStates+`
			 AND ($3::uuid[] IS NULL OR f.application_id = ANY($3))
			 AND `+controlBreaksSQL+`
			GROUP BY c.id`, tenantID, raw, apps)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var d ControlDeadline
			if err := rows.Scan(&id, &d.Open, &d.Overdue, &d.Earliest); err != nil {
				return err
			}
			out[id] = d
		}
		return rows.Err()
	})
	return out, err
}
