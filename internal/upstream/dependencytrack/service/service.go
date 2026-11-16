// Package service runs the Dependency-Track integration inside the server (docs/10 §9, docs/16 D92, docs/23 K5):
// the dtrack_sync jobs, the schedule that starts them, and the per-source syncer built from the ScanSource and its
// Connector.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/domain"
	"rampart/internal/jobs"
	"rampart/internal/store"
	dtclient "rampart/internal/upstream/dependencytrack/client"
	dtsync "rampart/internal/upstream/dependencytrack/sync"
)

// Store is what one sync needs, read under the job's tenant.
type Store interface {
	dtsync.Store
	store.DTrackSources
	GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error)
	GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error)
}

// SourceLister lists the Dependency-Track sources of every tenant; it needs the system role.
type SourceLister interface {
	ListDTrackSources(ctx context.Context) ([]store.DTrackSource, error)
}

// SecretResolver reads a stored secret (the connector's API key).
type SecretResolver interface {
	GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error)
}

// Queue is the dtrack-sync River queue.
type Queue interface {
	EnqueueDTrackSync(ctx context.Context, args jobs.DTrackSyncJobArgs, delay time.Duration) error
	EnqueueDTrackProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, delay time.Duration) error
}

// HTTPFor gives the SSRF-safe HTTP client and allowlist scoped to a tenant's Dependency-Track connectors (D77).
type HTTPFor func(tenantID uuid.UUID) (dtclient.HTTPDoer, *domain.PlatformSSRFAllowlist)

// Service runs the Dependency-Track jobs.
type Service struct {
	store   Store
	sources SourceLister
	secrets SecretResolver
	http    HTTPFor
	merge   dtsync.MergeEngine
	queue   Queue
	log     *slog.Logger
	now     func() time.Time
}

// New builds the service.
func New(st Store, sources SourceLister, secrets SecretResolver, http HTTPFor, merge dtsync.MergeEngine, queue Queue, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, sources: sources, secrets: secrets, http: http, merge: merge, queue: queue,
		log: log.With("component", "dtrack"), now: time.Now}
}

// ErrNotConfigured is a permanent failure: the source or its connector is missing or not a Dependency-Track one.
var ErrNotConfigured = errors.New("dependency-track source is not configured")

// Syncer builds the syncer of one source: its connector's URL and key, its mapping rules and filters.
func (s *Service) Syncer(ctx context.Context, tenantID, sourceID uuid.UUID) (*dtsync.Syncer, *store.DTrackSource, error) {
	src, err := s.store.GetDTrackSource(ctx, tenantID, sourceID)
	if err != nil {
		return nil, nil, &jobs.PermanentError{Code: "dtrack_source", Err: fmt.Errorf("%w: %v", ErrNotConfigured, err)}
	}
	conn, err := s.store.GetConnector(ctx, tenantID, src.Connector)
	if err != nil || conn == nil || conn.Type != domain.ConnectorTypeDependencyTrack || conn.Spec.DependencyTrack == nil {
		return nil, nil, &jobs.PermanentError{Code: "dtrack_connector", Err: fmt.Errorf("%w: connector %q is not a dependencyTrack connector of this tenant", ErrNotConfigured, src.Connector)}
	}
	key := conn.Spec.DependencyTrack.CredentialsSecretRef.Key
	if key == "" {
		key = "apiKey"
	}
	apiKey, err := s.secrets.GetSecretMaterial(ctx, tenantID, domain.ConnectorSecretStorageKey(conn.Name, key))
	if err != nil || len(strings.TrimSpace(string(apiKey))) == 0 {
		return nil, nil, fmt.Errorf("dependency-track connector %q: the API key is not readable yet", conn.Name)
	}
	doer, allow := s.http(tenantID)
	client := dtclient.NewClient(dtclient.Config{BaseURL: conn.Spec.DependencyTrack.URL, APIKey: string(apiKey), Client: doer, Allowlist: allow, Timeout: 30 * time.Second})

	m := src.Spec.Mapping
	rules := make([]dtsync.CELRule, 0, len(m.Rules))
	for _, r := range m.Rules {
		rules = append(rules, dtsync.CELRule{When: r.When, Application: r.Application})
	}
	engine, err := dtsync.NewMappingEngine(dtsync.MappingConfig{
		UseProjectProperties: m.UseProps(), TagPrefix: m.TagPrefix, MatchExistingAssets: m.MatchAssets(),
		ParentAsApplication: m.ParentAsApplication, CELRules: rules, DefaultApplication: m.DefaultApplication,
	}, s.store, s.store)
	if err != nil {
		return nil, nil, &jobs.PermanentError{Code: "dtrack_mapping", Err: err}
	}
	syncer := dtsync.NewSyncer(client, s.store, s.merge, engine)
	syncer.Configure(dtsync.Config{Connector: conn.Name, Spec: src.Spec}, s.queue)
	return syncer, src, nil
}

// Handle runs one dtrack_sync job.
func (s *Service) Handle(ctx context.Context, args jobs.DTrackSyncJobArgs) error {
	syncer, _, err := s.Syncer(ctx, args.TenantID, args.SourceID)
	if err != nil {
		if args.ProjectUUID != "" {
			_, _ = s.store.CompleteDTrackSync(ctx, args.TenantID, args.ProjectUUID, err)
		} else {
			_ = s.store.RecordPortfolioSync(ctx, args.TenantID, args.SourceID, s.now().UTC(), err)
		}
		return err
	}
	if args.ProjectUUID != "" {
		return syncer.SyncProject(ctx, args.TenantID, args.SourceID, args.ProjectUUID)
	}
	err = syncer.SyncPortfolio(ctx, args.TenantID, args.SourceID)
	if rerr := s.store.RecordPortfolioSync(ctx, args.TenantID, args.SourceID, s.now().UTC(), err); rerr != nil {
		s.log.Warn("recording the portfolio sync failed", "error", rerr)
	}
	return err
}

// Due says which sources need a portfolio sync now: never synced, or synced longer ago than their schedule.
func Due(sources []store.DTrackSource, now time.Time) []store.DTrackSource {
	var out []store.DTrackSource
	for _, src := range sources {
		if src.LastPortfolioSync == nil || now.Sub(*src.LastPortfolioSync) >= src.Schedule {
			out = append(out, src)
		}
	}
	return out
}

// Tick enqueues the portfolio sync of every source that is due. DT sends nothing when an analysis ends (docs/23
// DT1), so the schedule is part of v1, not a fallback.
func (s *Service) Tick(ctx context.Context) int {
	all, err := s.sources.ListDTrackSources(ctx)
	if err != nil {
		s.log.Warn("listing dependency-track sources failed", "error", err)
		return 0
	}
	n := 0
	now := s.now().UTC()
	for _, src := range Due(all, now) {
		// Recorded before the job runs, so a slow portfolio is not enqueued again on the next tick.
		_ = s.store.RecordPortfolioSync(ctx, src.TenantID, src.ID, now, nil)
		if err := s.queue.EnqueueDTrackSync(ctx, jobs.DTrackSyncJobArgs{TenantID: src.TenantID, SourceID: src.ID}, 0); err != nil {
			s.log.Warn("enqueuing a portfolio sync failed", "source", src.Name, "error", err)
			continue
		}
		n++
	}
	return n
}

// RunScheduler ticks every minute; one replica at a time holds the advisory lock.
func (s *Service) RunScheduler(ctx context.Context, pool *pgxpool.Pool) {
	const lockKey = int64(0x52414d50_44545343) // "RAMPDTSC"
	pass := func() {
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
		if n := s.Tick(ctx); n > 0 {
			s.log.Info("dependency-track portfolio syncs enqueued", "sources", n)
		}
	}
	pass()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}
