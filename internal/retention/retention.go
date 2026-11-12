// Package retention removes data whose time is up (docs/01 H7, docs/04 RetentionPolicy, docs/16 D53).
//
// Two kinds of work, with two kinds of rights:
//   - Tenant data (stale occurrences, old resolved findings, run results, old finding keys, raw reports) is
//     removed per tenant as the application role, under row-level security, in small batches. Each tenant that
//     lost anything gets one audit entry saying what and how much (ISO/IEC 27001:2022 A.8.10 asks for evidence of
//     deletion).
//   - The partitioned logs (finding_event, audit_event) are maintained by the owner role: the next months'
//     partitions are created (D4) and months past retention are dropped whole (D46: nobody deletes audit rows).
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/objectstore"
	"rampart/internal/store"
)

// Store is what the tenant sweep needs, as the application role.
type Store interface {
	PurgeAbsentOccurrences(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error)
	PurgeResolvedFindings(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error)
	PurgeRunResults(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error)
	PurgeKeyAliases(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int64, error)
	ExpiredReports(ctx context.Context, tenantID uuid.UUID, abandonedBefore, secretBefore, rawBefore time.Time, limit int) ([]store.ExpiredReport, error)
	MarkReportPurged(ctx context.Context, tenantID, uploadID uuid.UUID, at time.Time) error
	RecordAudit(ctx context.Context, e auth.AuditEvent) error
}

// Tenants lists every tenant (rampart_system).
type Tenants func(ctx context.Context) ([]uuid.UUID, error)

// Sweeper applies one retention policy.
type Sweeper struct {
	store   Store
	tenants Tenants
	objects objectstore.Store // nil: no raw reports are stored, so none are removed
	owner   *pgxpool.Pool     // nil: partitions are left to `rampart maintenance` (the Helm CronJob)
	policy  domain.RetentionPolicy
	log     *slog.Logger
	now     func() time.Time
}

// New returns a Sweeper. The policy must have passed Validate.
func New(st Store, tenants Tenants, objects objectstore.Store, owner *pgxpool.Pool, policy domain.RetentionPolicy, log *slog.Logger) *Sweeper {
	return &Sweeper{store: st, tenants: tenants, objects: objects, owner: owner, policy: policy, log: log,
		now: func() time.Time { return time.Now().UTC() }}
}

// TenantResult says what one tenant lost.
type TenantResult struct {
	Occurrences      int64 `json:"occurrences"`
	ResolvedFindings int64 `json:"resolved_findings"`
	RunResults       int64 `json:"run_results"`
	KeyAliases       int64 `json:"key_aliases"`
	Reports          int64 `json:"raw_reports"`
	AbandonedUploads int64 `json:"abandoned_uploads"`
}

func (r TenantResult) total() int64 {
	return r.Occurrences + r.ResolvedFindings + r.RunResults + r.KeyAliases + r.Reports + r.AbandonedUploads
}

// reportsPerPass bounds the object deletions of one tenant in one sweep; the rest wait for the next.
const reportsPerPass = 1000

// sweepTenant removes one tenant's expired data. It stops at the first error and returns what it did so far;
// what is left is picked up by the next sweep, because every step only removes what is already expired.
func (s *Sweeper) sweepTenant(ctx context.Context, tenantID uuid.UUID) (TenantResult, error) {
	var res TenantResult
	now := s.now()
	p := s.policy
	var err error
	if c := domain.Cutoff(now, p.OccurrencesDays); !c.IsZero() {
		if res.Occurrences, err = s.store.PurgeAbsentOccurrences(ctx, tenantID, c); err != nil {
			return res, err
		}
		if res.KeyAliases, err = s.store.PurgeKeyAliases(ctx, tenantID, c); err != nil {
			return res, err
		}
	}
	if c := domain.Cutoff(now, p.ResolvedFindingsDays); !c.IsZero() {
		if res.ResolvedFindings, err = s.store.PurgeResolvedFindings(ctx, tenantID, c); err != nil {
			return res, err
		}
	}
	if c := domain.Cutoff(now, p.RunResultsDays); !c.IsZero() {
		if res.RunResults, err = s.store.PurgeRunResults(ctx, tenantID, c); err != nil {
			return res, err
		}
	}
	if s.objects != nil {
		expired, err := s.store.ExpiredReports(ctx, tenantID, now.Add(-domain.AbandonedUploadAfter),
			domain.Cutoff(now, p.SecretReportsDays), domain.Cutoff(now, p.RawReportsDays), reportsPerPass)
		if err != nil {
			return res, err
		}
		for _, r := range expired {
			// The object first, then the row: if the row update fails, the next sweep deletes again (a missing
			// object is not an error), so a report can never be marked gone while it is still stored.
			if err := s.objects.Delete(ctx, r.ObjectRef); err != nil {
				return res, err
			}
			if err := s.store.MarkReportPurged(ctx, tenantID, r.UploadID, now); err != nil {
				return res, err
			}
			if r.Abandoned {
				res.AbandonedUploads++
			} else {
				res.Reports++
			}
		}
	}
	return res, nil
}

// SweepTenant removes one tenant's expired data and, when anything went, records it in that tenant's audit log.
func (s *Sweeper) SweepTenant(ctx context.Context, tenantID uuid.UUID) (TenantResult, error) {
	res, err := s.sweepTenant(ctx, tenantID)
	if res.total() > 0 {
		s.audit(ctx, tenantID, res)
	}
	return res, err
}

// Sweep maintains the logs (when it has the owner role) and then every tenant. One tenant's failure is logged
// and does not stop the others.
func (s *Sweeper) Sweep(ctx context.Context) {
	if s.owner != nil {
		if err := MaintainLogs(ctx, s.owner, s.policy, s.now(), s.log); err != nil {
			s.log.Warn("retention: maintaining the event and audit partitions failed", "error", err)
		}
	}
	tenants, err := s.tenants(ctx)
	if err != nil {
		s.log.Warn("retention: listing tenants failed", "error", err)
		return
	}
	for _, t := range tenants {
		res, err := s.SweepTenant(ctx, t)
		if res.total() > 0 {
			s.log.Info("retention removed expired data", "tenant", t, "occurrences", res.Occurrences,
				"resolved_findings", res.ResolvedFindings, "run_results", res.RunResults, "key_aliases", res.KeyAliases,
				"raw_reports", res.Reports, "abandoned_uploads", res.AbandonedUploads)
		}
		if err != nil {
			s.log.Warn("retention failed for a tenant", "tenant", t, "error", err)
		}
	}
}

// audit records a deletion as evidence: what kind, how many, and the policy that decided it.
func (s *Sweeper) audit(ctx context.Context, tenantID uuid.UUID, res TenantResult) {
	err := s.store.RecordAudit(ctx, auth.AuditEvent{
		TenantID: tenantID, Actor: "system:retention", Action: "retention.purge", ResourceType: "tenant", ResourceID: tenantID.String(),
		Detail: map[string]any{"removed": res, "policy": s.policy},
	})
	if err != nil {
		s.log.Warn("retention: recording the audit entry failed", "tenant", tenantID, "error", err)
	}
}

// MaintainLogs creates the event and audit partitions of the coming months and drops the months past
// retention. It needs the owner role.
func MaintainLogs(ctx context.Context, owner *pgxpool.Pool, policy domain.RetentionPolicy, now time.Time, log *slog.Logger) error {
	if err := store.MaintainPartitions(ctx, owner, now); err != nil {
		return err
	}
	dropped, err := store.DropExpiredPartitions(ctx, owner, domain.Cutoff(now, policy.EventsDays), domain.Cutoff(now, policy.AuditDays))
	if len(dropped.Partitions) > 0 || dropped.DefaultRows > 0 {
		log.Info("retention dropped expired log months", "partitions", dropped.Partitions, "default_rows", dropped.DefaultRows)
	}
	return err
}

// Run sweeps now and then every interval. Only one replica sweeps at a time: lockPool (rampart_system) holds a
// session advisory lock for the length of a sweep.
func Run(ctx context.Context, s *Sweeper, lockPool *pgxpool.Pool, interval time.Duration) {
	const lockKey = int64(0x52414d50_52455445) // "RAMPRETE"
	sweep := func() {
		if lockPool != nil {
			conn, err := lockPool.Acquire(ctx)
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
		s.Sweep(ctx)
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
