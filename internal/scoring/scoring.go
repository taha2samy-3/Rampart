// Package scoring computes and stores each finding's risk score, band and SLA, keeps them current when threat
// intelligence changes, and finds the findings whose SLA has run out (docs/06, docs/16 D28 and D40).
package scoring

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/risk"
	"rampart/internal/store"
)

// Intel looks up KEV and EPSS for vulnerability ids (the global vulnerability table, D19).
type Intel interface {
	Lookup(ctx context.Context, ids []string) (*enrich.FeedStore, error)
}

// PolicySource says which SLA policy applies to a tenant. The built-in one is the default; a tenant's
// SLAPolicy object replaces it when one exists.
type PolicySource interface {
	SLAPolicy(ctx context.Context, tenantID uuid.UUID) domain.SLAPolicy
}

// BuiltinPolicy always answers with the policy of docs/06 section 4.
type BuiltinPolicy struct{}

// SLAPolicy returns the built-in policy.
func (BuiltinPolicy) SLAPolicy(context.Context, uuid.UUID) domain.SLAPolicy {
	return domain.DefaultSLAPolicy()
}

// Scorer fills the score, band, KEV, EPSS bucket and SLA of findings.
type Scorer struct {
	store  store.Store
	intel  Intel
	policy PolicySource
	now    func() time.Time
}

// New returns a Scorer. intel may be nil (no threat intelligence: the score has its severity and context only).
func New(s store.Store, intel Intel, policy PolicySource) *Scorer {
	if policy == nil {
		policy = BuiltinPolicy{}
	}
	return &Scorer{store: s, intel: intel, policy: policy, now: func() time.Time { return time.Now().UTC() }}
}

// Policy exposes the SLA policy of a tenant, for the steps that move the clock (risk acceptance).
func (s *Scorer) Policy(ctx context.Context, tenantID uuid.UUID) domain.SLAPolicy {
	return s.policy.SLAPolicy(ctx, tenantID)
}

// EPSSBucket names an exploitation probability: high from 50 %, moderate from 10 %, else low (docs/06).
func EPSSBucket(epss float64) string {
	switch {
	case epss >= 0.5:
		return "high"
	case epss >= 0.1:
		return "moderate"
	case epss > 0:
		return "low"
	}
	return ""
}

// ScoreBatch scores findings of one application. It stores nothing: the caller writes the findings. The stored
// score has no time-dependent factor (D28): the age of a finding is evaluated when it is read, not stored.
func (s *Scorer) ScoreBatch(ctx context.Context, tenantID, applicationID uuid.UUID, fs []*domain.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	var app *domain.Application
	if applicationID != uuid.Nil {
		if a, err := s.store.GetApplication(ctx, tenantID, applicationID); err == nil {
			app = a
		}
	}
	feeds := enrich.NewFeedStore()
	if s.intel != nil {
		var ids []string
		for _, f := range fs {
			if f.VulnerabilityID != nil && *f.VulnerabilityID != "" {
				ids = append(ids, *f.VulnerabilityID)
			}
		}
		if len(ids) > 0 {
			if got, err := s.intel.Lookup(ctx, ids); err == nil {
				feeds = got
			} else {
				slog.Warn("threat intelligence lookup failed; scoring without it", "error", err)
			}
		}
	}
	policy := s.policy.SLAPolicy(ctx, tenantID)
	now := s.now()
	for _, f := range fs {
		Apply(f, app, feeds, policy, now)
	}
	return nil
}

// Breakdown is the explainable score of a finding: its severity, the intelligence in feeds, and the context of
// its application. It has no age factor (D28). It also returns the application criticality the SLA uses.
func Breakdown(f *domain.Finding, app *domain.Application, feeds *enrich.FeedStore, now time.Time) (risk.ScoreBreakdown, string) {
	var vulnIDs []string
	if f.VulnerabilityID != nil && *f.VulnerabilityID != "" {
		vulnIDs = []string{*f.VulnerabilityID}
	}
	ctx := risk.Context{Environment: f.Track, Now: now}
	criticality := "low"
	if app != nil {
		criticality = strings.ToLower(app.BusinessCriticality)
		ctx.BusinessCriticality = criticality
		ctx.IsInternetFacing = app.InternetFacing
		for _, c := range app.DataClassification {
			if c = strings.ToLower(c); c == "pci" || c == "pii" || c == "phi" {
				ctx.HasSensitiveData = true
			}
		}
	}
	return risk.EvaluateRisk(domain.RawFinding{Severity: f.Severity, RuleID: f.RuleID, Title: f.Title}, vulnIDs, ctx, feeds), criticality
}

// Explain is Breakdown for the API: the same numbers that are stored, read with the current intelligence.
// apps caches applications for the length of one request.
func (s *Scorer) Explain(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, feeds *enrich.FeedStore, apps map[uuid.UUID]*domain.Application) risk.ScoreBreakdown {
	app, ok := apps[f.ApplicationID]
	if !ok {
		if a, err := s.store.GetApplication(ctx, tenantID, f.ApplicationID); err == nil {
			app = a
		}
		apps[f.ApplicationID] = app
	}
	b, _ := Breakdown(f, app, feeds, s.now())
	return b
}

// Apply scores one finding in place from its application, the intelligence in feeds, and the SLA policy.
func Apply(f *domain.Finding, app *domain.Application, feeds *enrich.FeedStore, policy domain.SLAPolicy, now time.Time) {
	b, criticality := Breakdown(f, app, feeds, now)
	f.RiskScore, f.RiskBand, f.KEV = b.TotalScore, b.Band, b.HasKEV
	f.EPSSBucket = EPSSBucket(b.EPSSScore)

	var kevDue *time.Time
	if f.VulnerabilityID != nil {
		if e, ok := feeds.GetKEV(*f.VulnerabilityID); ok && e.DueDate != nil {
			kevDue = e.DueDate
		}
	}
	setSLA(f, criticality, kevDue, policy)
}

// setSLA moves the due date of an active finding to what the policy says for its band (docs/06 section 4):
// from the original start, never later than a due date that has already been breached, and not at all while the
// clock is paused.
func setSLA(f *domain.Finding, criticality string, kevDue *time.Time, policy domain.SLAPolicy) {
	if f.SLAStart == nil {
		start := f.FirstSeen
		if start.IsZero() {
			return
		}
		f.SLAStart = &start
	}
	if !f.State.IsActive() || f.SLAPausedAt != nil {
		return
	}
	due := policy.Due(f.RiskBand, criticality, *f.SLAStart, kevDue)
	if f.SLABreachedAt != nil && f.SLADue != nil && due.After(*f.SLADue) {
		return // a re-score never gives back time that has already run out
	}
	f.SLADue = &due
}

// Rescore re-scores the active findings of a tenant that have a vulnerability id, and stores those whose score,
// band, KEV, EPSS bucket or due date changed. It runs after the feeds change (docs/16 D28: an EPSS or KEV change
// re-scores). It returns how many findings changed.
func (s *Scorer) Rescore(ctx context.Context, tenantID uuid.UUID) (int, error) {
	changed := 0
	after := uuid.Nil
	for {
		page, err := s.store.ListFindingsForRescore(ctx, tenantID, after, 500)
		if err != nil {
			return changed, err
		}
		if len(page) == 0 {
			return changed, nil
		}
		after = page[len(page)-1].ID
		before := make(map[uuid.UUID]domain.Finding, len(page))
		for _, f := range page {
			before[f.ID] = *f
		}
		// One application per finding: group, so each is read once.
		byApp := map[uuid.UUID][]*domain.Finding{}
		for _, f := range page {
			byApp[f.ApplicationID] = append(byApp[f.ApplicationID], f)
		}
		var dirty []*domain.Finding
		for app, fs := range byApp {
			if err := s.ScoreBatch(ctx, tenantID, app, fs); err != nil {
				return changed, err
			}
			for _, f := range fs {
				if riskChanged(before[f.ID], *f) {
					dirty = append(dirty, f)
				}
			}
		}
		if len(dirty) > 0 {
			if err := s.store.UpdateFindingRisk(ctx, tenantID, dirty); err != nil {
				return changed, err
			}
			changed += len(dirty)
		}
	}
}

func riskChanged(a, b domain.Finding) bool {
	same := func(x, y *time.Time) bool {
		if x == nil || y == nil {
			return x == y
		}
		return x.Equal(*y)
	}
	return a.RiskScore != b.RiskScore || a.RiskBand != b.RiskBand || a.KEV != b.KEV || a.EPSSBucket != b.EPSSBucket || !same(a.SLADue, b.SLADue) || !same(a.SLAStart, b.SLAStart)
}

// MarkBreaches records, for a tenant, every active, unpaused finding whose due date has passed and that was not
// yet marked, and puts `sla_breached` on its timeline. It returns how many it marked.
func (s *Scorer) MarkBreaches(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	ids, err := s.store.MarkSLABreaches(ctx, tenantID, now)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	events := make([]*domain.FindingEvent, 0, len(ids))
	for _, id := range ids {
		events = append(events, &domain.FindingEvent{ID: domain.NewID(), FindingID: id, At: now, Actor: "system:sla", Type: "sla_breached"})
	}
	return len(ids), s.store.RecordFindingEvents(ctx, tenantID, events)
}

// RunSweeper marks breaches for every tenant every interval. One replica sweeps at a time (an advisory lock).
func RunSweeper(ctx context.Context, sc *Scorer, sys store.Store, pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) {
	const lockKey = int64(0x52414d50_534c4121) // "RAMPSLA!"
	sweep := func() {
		if pool != nil {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			var got bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
				return
			}
			defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()
		}
		tenants, err := sys.ListTenantIDs(ctx)
		if err != nil {
			log.Warn("sla sweep: listing tenants failed", "error", err)
			return
		}
		now := time.Now().UTC()
		for _, t := range tenants {
			if n, err := sc.MarkBreaches(ctx, t, now); err != nil {
				log.Warn("sla sweep failed", "tenant", t, "error", err)
			} else if n > 0 {
				log.Info("sla breaches marked", "tenant", t, "count", n)
			}
		}
	}
	sweep()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sweep()
		}
	}
}

// RescoreAll re-scores every tenant. It is what runs after a feed sync.
func RescoreAll(ctx context.Context, sc *Scorer, sys store.Store, log *slog.Logger) {
	tenants, err := sys.ListTenantIDs(ctx)
	if err != nil {
		log.Warn("rescore: listing tenants failed", "error", err)
		return
	}
	for _, t := range tenants {
		n, err := sc.Rescore(ctx, t)
		if err != nil {
			log.Warn("rescore failed", "tenant", t, "error", err)
			continue
		}
		if n > 0 {
			log.Info("findings re-scored", "tenant", t, "count", n)
		}
	}
}
