// Package workflow holds the multi-step decisions of triage: risk acceptance, with its approval and expiry
// (docs/06 section 6, docs/16 D39). Every step runs in one tenant transaction.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/domain"
	"rampart/internal/scoring"
	"rampart/internal/store"
)

// Service runs risk-acceptance steps against a store.
type Service struct {
	store  store.Store
	scorer *scoring.Scorer // optional: it carries the SLA policy and re-scores a finding whose clock moved
	now    func() time.Time
}

// SetScorer lets the service pause and resume the SLA clock of the findings it accepts and releases.
func (s *Service) SetScorer(sc *scoring.Scorer) { s.scorer = sc }

func (s *Service) policy(ctx context.Context, tenantID uuid.UUID) domain.SLAPolicy {
	if s.scorer != nil {
		return s.scorer.Policy(ctx, tenantID)
	}
	return domain.DefaultSLAPolicy()
}

// New returns a Service.
func New(s store.Store) *Service {
	return &Service{store: s, now: func() time.Time { return time.Now().UTC() }}
}

// Outcome says what a step did to the findings of an acceptance.
type Outcome struct {
	Acceptance *domain.RiskAcceptance `json:"acceptance"`
	Applied    int                    `json:"applied"`
	// Skipped lists findings the acceptance could not be applied to, with why (they changed since the request).
	Skipped []Skipped `json:"skipped"`
}

// Skipped is a finding a step left alone.
type Skipped struct {
	FindingID uuid.UUID `json:"finding_id"`
	Reason    string    `json:"reason"`
}

// AutoApprover is the approver recorded when the tenant does not require approval.
const AutoApprover = "system:auto"

func refuse(format string, a ...any) error {
	return &domain.TriageError{Msg: fmt.Sprintf(format, a...)}
}

// Request files an acceptance. Without tenant approval it is approved at once and applied; with it, it waits.
func (s *Service) Request(ctx context.Context, tenantID uuid.UUID, requester string, req domain.RiskAcceptanceRequest) (*Outcome, error) {
	settings, err := s.store.GetTenantSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	ra, err := domain.NewRiskAcceptance(req, requester, settings, now)
	if err != nil {
		return nil, err
	}
	ra.TenantID = tenantID
	var out *Outcome
	err = s.store.InTenantTx(ctx, tenantID, func(st store.Store) error {
		// Every finding must exist, still be active, and not be under another acceptance already.
		covered, err := st.FindingsUnderAcceptance(ctx, tenantID, ra.FindingIDs)
		if err != nil {
			return err
		}
		for _, id := range ra.FindingIDs {
			f, _, err := st.GetFinding(ctx, tenantID, id)
			if err != nil || f == nil {
				return refuse("finding %s was not found", id)
			}
			if other, ok := covered[id]; ok {
				return refuse("finding %s is already covered by risk acceptance %s", id, other)
			}
			if !f.State.IsActive() {
				return refuse("finding %s is %s: only an open, under-investigation or affected finding can have its risk accepted", id, f.State)
			}
		}
		if !settings.RiskAcceptanceApproval {
			ra.Status, ra.Approver, ra.DecidedAt = domain.AcceptanceApproved, AutoApprover, &now
		}
		if err := st.CreateRiskAcceptance(ctx, tenantID, ra); err != nil {
			return err
		}
		out = &Outcome{Acceptance: ra, Skipped: []Skipped{}}
		if ra.Status == domain.AcceptanceApproved {
			applied, skipped, err := s.apply(ctx, st, ra, requester, now)
			out.Applied, out.Skipped = applied, skipped
			return err
		}
		return s.note(ctx, st, ra, "risk_acceptance_requested", requester, now, ra.Justification)
	})
	return out, err
}

// Approve lets someone other than the requester approve a pending acceptance, which puts its findings in risk_accepted.
func (s *Service) Approve(ctx context.Context, tenantID, id uuid.UUID, approver string) (*Outcome, error) {
	var out *Outcome
	now := s.now()
	err := s.store.InTenantTx(ctx, tenantID, func(st store.Store) error {
		ra, err := st.GetRiskAcceptance(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if ra.Status != domain.AcceptancePending {
			return refuse("this risk acceptance is %s, not pending", ra.Status)
		}
		if ra.Requester == approver {
			return refuse("the person who asked cannot approve their own risk acceptance")
		}
		if err := st.SetRiskAcceptanceStatus(ctx, tenantID, id, domain.AcceptancePending, domain.AcceptanceApproved, approver, "", now); err != nil {
			return err
		}
		ra.Status, ra.Approver, ra.DecidedAt = domain.AcceptanceApproved, approver, &now
		applied, skipped, err := s.apply(ctx, st, ra, approver, now)
		out = &Outcome{Acceptance: ra, Applied: applied, Skipped: skipped}
		return err
	})
	return out, err
}

// Reject turns a pending acceptance down, with a reason the requester can read.
func (s *Service) Reject(ctx context.Context, tenantID, id uuid.UUID, by, reason string) (*domain.RiskAcceptance, error) {
	if reason == "" {
		return nil, refuse("say why it is rejected: the requester will read it")
	}
	var ra *domain.RiskAcceptance
	now := s.now()
	err := s.store.InTenantTx(ctx, tenantID, func(st store.Store) error {
		var err error
		if ra, err = st.GetRiskAcceptance(ctx, tenantID, id); err != nil {
			return err
		}
		if ra.Status != domain.AcceptancePending {
			return refuse("this risk acceptance is %s, not pending", ra.Status)
		}
		if err := st.SetRiskAcceptanceStatus(ctx, tenantID, id, domain.AcceptancePending, domain.AcceptanceRejected, by, reason, now); err != nil {
			return err
		}
		ra.Status, ra.Approver, ra.DecisionNote, ra.DecidedAt = domain.AcceptanceRejected, by, reason, &now
		return s.note(ctx, st, ra, "risk_acceptance_rejected", by, now, reason)
	})
	return ra, err
}

// Revoke ends an acceptance early (or withdraws a pending one). Findings it still holds go back to where they came from.
func (s *Service) Revoke(ctx context.Context, tenantID, id uuid.UUID, by, reason string) (*Outcome, error) {
	var out *Outcome
	now := s.now()
	err := s.store.InTenantTx(ctx, tenantID, func(st store.Store) error {
		ra, err := st.GetRiskAcceptance(ctx, tenantID, id)
		if err != nil {
			return err
		}
		from := ra.Status
		if from != domain.AcceptancePending && from != domain.AcceptanceApproved {
			return refuse("this risk acceptance is %s and cannot be revoked", from)
		}
		if err := st.SetRiskAcceptanceStatus(ctx, tenantID, id, from, domain.AcceptanceRevoked, by, reason, now); err != nil {
			return err
		}
		ra.Status, ra.DecisionNote, ra.DecidedAt = domain.AcceptanceRevoked, reason, &now
		out = &Outcome{Acceptance: ra, Skipped: []Skipped{}}
		if from == domain.AcceptancePending {
			return s.note(ctx, st, ra, "risk_acceptance_revoked", by, now, reason)
		}
		n, err := s.release(ctx, st, ra, by, now, true, "revoked", reason)
		out.Applied = n
		return err
	})
	return out, err
}

// ExpireDue ends every approved acceptance of the tenant whose expiry has passed, as its onExpiry says
// (docs/16 D18): reactivate returns each finding to where it came from, or resolves it when no scanner reports
// it any more; notify_only leaves the findings accepted and says so on their timeline.
func (s *Service) ExpireDue(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	due, err := s.store.ListDueAcceptances(ctx, tenantID, now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ra := range due {
		err := s.store.InTenantTx(ctx, tenantID, func(st store.Store) error {
			if err := st.SetRiskAcceptanceStatus(ctx, tenantID, ra.ID, domain.AcceptanceApproved, domain.AcceptanceExpired, "system:expiry", "", now); err != nil {
				return err
			}
			ra.Status = domain.AcceptanceExpired
			_, err := s.release(ctx, st, ra, "system:expiry", now, ra.OnExpiry == domain.OnExpiryReactivate, "expired", "")
			return err
		})
		if errors.Is(err, store.ErrVersionConflict) { // someone revoked it between the list and now
			continue
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// apply puts the findings of an approved acceptance into risk_accepted. A finding that stopped being active since
// the request is skipped, with a reason, and the rest still go through.
func (s *Service) apply(ctx context.Context, st store.Store, ra *domain.RiskAcceptance, actor string, now time.Time) (int, []Skipped, error) {
	skipped := []Skipped{}
	applied := 0
	for _, id := range ra.FindingIDs {
		f, _, err := st.GetFinding(ctx, ra.TenantID, id)
		if err != nil || f == nil {
			skipped = append(skipped, Skipped{id, "the finding no longer exists"})
			continue
		}
		if !f.State.IsActive() {
			skipped = append(skipped, Skipped{id, "the finding is " + string(f.State) + ", not open, under investigation or affected"})
			continue
		}
		version := f.Version
		rid := ra.ID
		note := "risk acceptance " + ra.ID.String() + ": " + ra.Justification
		events, err := domain.ApplyTriage(f, domain.TriageRequest{State: domain.StateRiskAccepted, Note: note, ViaRiskAcceptance: true, RiskAcceptanceID: &rid}, actor, now)
		if err != nil {
			return applied, skipped, err
		}
		events = append(events, &domain.FindingEvent{ID: domain.NewID(), FindingID: id, At: now, Actor: actor, Type: "risk_acceptance_approved", Note: ra.ID.String()})
		if s.policy(ctx, ra.TenantID).PauseDuringRiskAcceptance && f.SLAPausedAt == nil { // docs/06 section 4
			paused := now
			f.SLAPausedAt = &paused
		}
		if err := st.UpdateFindingTriage(ctx, ra.TenantID, f, version, events); err != nil {
			return applied, skipped, err
		}
		applied++
	}
	return applied, skipped, nil
}

// release takes the findings still held by an acceptance out of risk_accepted (when restore is set) and records
// why on each timeline. A finding someone already moved on is left alone.
func (s *Service) release(ctx context.Context, st store.Store, ra *domain.RiskAcceptance, actor string, now time.Time, restore bool, why, note string) (int, error) {
	n := 0
	for _, id := range ra.FindingIDs {
		f, _, err := st.GetFinding(ctx, ra.TenantID, id)
		if err != nil || f == nil || f.State != domain.StateRiskAccepted || f.RiskAcceptanceID == nil || *f.RiskAcceptanceID != ra.ID {
			continue
		}
		version := f.Version
		var events []*domain.FindingEvent
		if restore {
			target := restoreTarget(f)
			events, err = domain.ApplyTriage(f, domain.TriageRequest{State: target, Note: "risk acceptance " + why}, actor, now)
			if err != nil {
				return n, err
			}
			s.resumeSLA(ctx, f, ra, now)
		}
		events = append(events, &domain.FindingEvent{ID: domain.NewID(), FindingID: id, At: now, Actor: actor, Type: "risk_acceptance_" + why, Note: firstNonEmpty(note, ra.ID.String())})
		if err := st.UpdateFindingTriage(ctx, ra.TenantID, f, version, events); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// resumeSLA restarts the clock of a finding whose acceptance ended: the time it spent accepted is not counted
// (the due date moves by it), or the clock starts again from now when the acceptance says so (docs/06 section 4).
func (s *Service) resumeSLA(ctx context.Context, f *domain.Finding, ra *domain.RiskAcceptance, now time.Time) {
	if f.SLAPausedAt == nil {
		return
	}
	paused := now.Sub(*f.SLAPausedAt)
	f.SLAPausedAt = nil
	if ra.RestartSLAOnExpiry {
		f.SLAStart, f.SLADue, f.SLABreachedAt = &now, nil, nil
		s.rescore(ctx, f)
		return
	}
	// Shift the start with the due date, so a later re-score (which counts from the start) keeps the time that
	// was spent accepted out of the clock.
	if f.SLAStart != nil {
		start := f.SLAStart.Add(paused)
		f.SLAStart = &start
	}
	if f.SLADue != nil {
		due := f.SLADue.Add(paused)
		f.SLADue = &due
	}
	s.rescore(ctx, f)
}

// rescore recomputes the due date of an active finding whose clock moved.
func (s *Service) rescore(ctx context.Context, f *domain.Finding) {
	if s.scorer != nil && f.State.IsActive() {
		_ = s.scorer.ScoreBatch(ctx, f.TenantID, f.ApplicationID, []*domain.Finding{f})
	}
}

// restoreTarget is where a finding goes when its acceptance ends (docs/16 D18): resolved when no scanner reports
// it any more, else the disposition it had before, else open.
func restoreTarget(f *domain.Finding) domain.FindingState {
	if f.Detection == domain.DetectionAbsent {
		return domain.StateFixed
	}
	if f.PreviousState.IsActive() {
		return f.PreviousState
	}
	return domain.StateOpen
}

// note records an event on every finding of the acceptance, without changing them.
func (s *Service) note(ctx context.Context, st store.Store, ra *domain.RiskAcceptance, typ, actor string, at time.Time, text string) error {
	events := make([]*domain.FindingEvent, 0, len(ra.FindingIDs))
	for _, id := range ra.FindingIDs {
		events = append(events, &domain.FindingEvent{ID: domain.NewID(), FindingID: id, At: at, Actor: actor, Type: typ, Note: text})
	}
	return st.RecordFindingEvents(ctx, ra.TenantID, events)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// RunExpirySweeper ends due acceptances every interval, for every tenant that has one. Only one replica sweeps at
// a time (an advisory lock). sys must see every tenant (rampart_system); the steps themselves run as the
// application role through svc, one tenant per transaction.
func RunExpirySweeper(ctx context.Context, svc *Service, sys store.Store, pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) {
	const lockKey = int64(0x52414d50_45585052) // "RAMPEXPR"
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
		now := time.Now().UTC()
		tenants, err := sys.TenantsWithDueAcceptances(ctx, now)
		if err != nil {
			log.Warn("risk acceptance expiry: listing tenants failed", "error", err)
			return
		}
		for _, t := range tenants {
			n, err := svc.ExpireDue(ctx, t, now)
			if err != nil {
				log.Warn("risk acceptance expiry failed", "tenant", t, "error", err)
				continue
			}
			if n > 0 {
				log.Info("risk acceptances expired", "tenant", t, "count", n)
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
