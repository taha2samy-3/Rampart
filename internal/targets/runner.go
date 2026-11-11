package targets

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/query"
	"rampart/internal/store"
	"rampart/internal/telemetry"
	"rampart/internal/ui"
)

// Runner manages the lifecycle of the selected target components (ADR 0004).
type Runner struct {
	cfg    *config.Config
	logger *slog.Logger
	ops    *telemetry.OpsServer
}

// NewRunner creates a new multi-target runner.
func NewRunner(cfg *config.Config, logger *slog.Logger) *Runner {
	ops := telemetry.NewOpsServer(cfg.Server.OpsAddr)
	return &Runner{
		cfg:    cfg,
		logger: logger,
		ops:    ops,
	}
}

// Run boots the target(s) specified in cfg.Target and manages graceful shutdown.
func (r *Runner) Run(ctx context.Context) error {
	r.logger.Info("starting rampart",
		"target", r.cfg.Target,
		"http_addr", r.cfg.Server.HTTPAddr,
		"ops_addr", r.cfg.Server.OpsAddr,
	)

	// 1. Initialize Storage Layer (Postgres with RLS per D4, or in-memory fallback)
	var (
		storeBackend store.Store
		pgStore      *store.PostgresStore
	)

	var sysStore *store.PostgresStore
	if r.cfg.Database.URL != "" {
		// D4: migrations run as rampart_owner, never as the application role.
		migrateURL := firstNonEmpty(r.cfg.Database.MigrateURL, r.cfg.Database.DirectURL)
		switch {
		case r.cfg.Database.AutoMigrate && migrateURL != "":
			r.logger.Info("applying database migrations (D4)")
			if err := store.AutoMigrate(ctx, migrateURL); err != nil {
				return fmt.Errorf("database migration failed: %w", err)
			}
		case r.cfg.Database.AutoMigrate:
			r.logger.Warn("database.autoMigrate is on but database.migrateUrl is not set; assuming the schema is managed by `rampart migrate`")
		}

		// No silent fallback: a configured database that is unreachable is a startup
		// failure, not a reason to keep running on an in-memory store that loses data.
		var err error
		pgStore, err = store.ConnectPostgres(ctx, r.cfg.Database.URL)
		if err != nil {
			return fmt.Errorf("connecting to postgres: %w", err)
		}
		defer pgStore.Close()
		storeBackend = pgStore
		r.logger.Info("connected to postgres (row-level security enforced)")

		if r.cfg.Database.SystemURL != "" {
			sysStore, err = store.ConnectPostgres(ctx, r.cfg.Database.SystemURL)
			if err != nil {
				return fmt.Errorf("connecting to postgres as rampart_system: %w", err)
			}
			defer sysStore.Close()
		}
	} else {
		r.logger.Warn("no database configured: running on the in-memory store, data is lost on restart")
		storeBackend = ingest.NewMemoryStore()
	}

	// 2. Initialize Ops server in background (:9090) with DB readiness probe
	if pgStore != nil {
		r.ops = telemetry.NewOpsServer(r.cfg.Server.OpsAddr, func(c context.Context) error {
			return pgStore.Pool().Ping(c)
		})
	}

	errOpsChan := make(chan error, 1)
	go func() {
		if err := r.ops.Start(); err != nil && err != http.ErrServerClosed {
			errOpsChan <- fmt.Errorf("ops server error: %w", err)
		}
	}()

	// 3. Tenancy and authentication (D8, D3)
	defaultTenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	var systemBackend store.Store // stays a true nil interface when there is no system pool
	if sysStore != nil {
		systemBackend = sysStore
	}
	if err := r.ensureDefaultTenant(ctx, storeBackend, systemBackend, defaultTenantID); err != nil {
		return err
	}

	authn := auth.NewAuthenticatorWithStore(storeBackend)
	if err := r.bootstrapAdminToken(ctx, authn, storeBackend, defaultTenantID, pgStore != nil); err != nil {
		return err
	}

	// 4. Parse selected targets
	targetList := strings.Split(r.cfg.Target, ",")
	isAll := false
	for _, t := range targetList {
		if strings.TrimSpace(t) == "all" {
			isAll = true
			break
		}
	}

	// 5. Initialize HTTP multiplexer for server.http.addr (:8080)
	mux := http.NewServeMux()

	if isAll || contains(targetList, "web-ui") {
		r.logger.Info("mounting web-ui workbench on / and /workbench")
		mux.Handle("/workbench", ui.Handler())
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/" {
				http.NotFound(w, req)
				return
			}
			if strings.Contains(req.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"product":"rampart","target":"%s","status":"running"}`, r.cfg.Target)
				return
			}
			ui.Handler().ServeHTTP(w, req)
		})
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"product":"rampart","target":"%s","status":"running"}`, r.cfg.Target)
		})
	}

	var queue jobs.JobQueue = jobs.NewInMemJobQueue()
	if pgStore != nil {
		directURL := firstNonEmpty(r.cfg.Database.DirectURL, r.cfg.Database.URL)
		riverQ, err := jobs.NewRiverQueue(ctx, pgStore.Pool(), directURL, nil)
		if err != nil {
			return fmt.Errorf("initializing river job queue: %w", err)
		}
		if err := riverQ.Start(ctx); err != nil {
			return fmt.Errorf("starting river job queue: %w", err)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = riverQ.Stop(stopCtx)
		}()
		queue = riverQ
		r.logger.Info("river job queue started (PostgreSQL backed)")
	}

	// D4: declarative configuration (tenants, namespaces, sources) is written by rampart_system.
	configBackend := storeBackend
	if systemBackend != nil {
		configBackend = systemBackend
	}
	r.autoApplyDefaultResources(ctx, configBackend)

	feeds := enrich.NewFeedStore()
	registry := integrations.DefaultRegistry()

	gw := ingest.NewGatewayWithDeps(queue, storeBackend, registry, feeds)
	gw.SetAuthenticator(authn)

	queryAPI := query.NewAPIWithAuth(storeBackend, feeds, authn)

	if isAll || contains(targetList, "ingest-gateway") {
		r.logger.Info("mounting ingest-gateway routes on /ingest/v1")
		gw.RegisterRoutes(mux)
	}

	if isAll || contains(targetList, "query-api") {
		r.logger.Info("mounting query-api routes on /api/v1")
		queryAPI.RegisterRoutes(mux)
	}

	httpServer := &http.Server{
		Addr:              r.cfg.Server.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errHTTPChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errHTTPChan <- fmt.Errorf("http server error: %w", err)
		}
	}()

	r.ops.SetReady(true)
	r.logger.Info("rampart initialized and ready to receive traffic")

	// Wait for context cancellation or unrecoverable server failure
	select {
	case <-ctx.Done():
		r.logger.Info("shutdown signal received, initiating graceful teardown")
	case err := <-errOpsChan:
		return err
	case err := <-errHTTPChan:
		return err
	}

	// Graceful shutdown with 10s deadline
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = r.ops.Shutdown(shutdownCtx)
	_ = httpServer.Shutdown(shutdownCtx)
	if pgStore != nil {
		pgStore.Close()
	}

	r.logger.Info("rampart shutdown complete")
	return nil
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if strings.TrimSpace(item) == val {
			return true
		}
	}
	return false
}

// ensureDefaultTenant creates the built-in tenant. Tenants are written by rampart_system
// (D4), so with Postgres and no system URL the tenant must already exist.
func (r *Runner) ensureDefaultTenant(ctx context.Context, app, sys store.Store, id uuid.UUID) error {
	if sys == nil {
		sys = app
	}
	err := sys.CreateTenant(ctx, &domain.Tenant{ID: id, Slug: "default", DisplayName: "Default Tenant", CreatedAt: time.Now().UTC()})
	if err == nil {
		return nil
	}
	if _, gerr := app.GetTenant(ctx, id); gerr == nil {
		return nil // already provisioned by the operator or a previous boot
	}
	return fmt.Errorf("default tenant is missing and could not be created (set database.systemUrl): %w", err)
}

// bootstrapAdminToken issues the first admin token. It is never written to the log
// when a database is used: it goes to auth.bootstrapAdminTokenFile (0600), once.
func (r *Runner) bootstrapAdminToken(ctx context.Context, authn *auth.Authenticator, _ store.Store, tenantID uuid.UUID, persistent bool) error {
	path := r.cfg.Auth.BootstrapAdminTokenFile
	if !persistent { // in-memory dev mode: nothing survives a restart anyway
		token := authn.DefaultAdminToken(tenantID)
		r.logger.Warn("dev mode admin token (in-memory store only)", "tenant_id", tenantID, "admin_token", token)
		return nil
	}
	if path == "" {
		r.logger.Warn("no auth.bootstrapAdminTokenFile set: no admin token was issued; create one with the CLI or set the file")
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil // token already issued on an earlier boot
	}
	token := authn.DefaultAdminToken(tenantID)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("writing bootstrap admin token: %w", err)
	}
	r.logger.Info("bootstrap admin token written", "path", path, "tenant_id", tenantID)
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (r *Runner) autoApplyDefaultResources(ctx context.Context, configStore store.Store) {
	candidates := []string{
		"/etc/rampart/resources.yaml",
		"/etc/rampart/resources.json",
		"deploy/compose/resources/default-resources.yaml",
		"deploy/compose/resources/default-resources.json",
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			var appStore apply.ConfigStore
			if cs, ok := configStore.(apply.ConfigStore); ok {
				appStore = cs
			} else {
				appStore = apply.NewMemoryConfigStore()
			}
			applier := apply.NewApplier(appStore)
			results, err := applier.ApplyMultiDocument(ctx, data)
			if err != nil {
				r.logger.Warn("failed to auto-apply declarative resources on boot", "path", path, "err", err)
			} else {
				r.logger.Info("auto-applied declarative resources on boot", "path", path, "count", len(results))
			}
			break
		}
	}
}
