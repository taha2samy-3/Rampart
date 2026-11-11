package targets

import (
	"context"
	"fmt"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log/slog"
	"net/http"
	"os"
	"rampart/internal/operator"
	"rampart/internal/secrets"
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
	"rampart/internal/version"
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

	// OpenTelemetry (D6): real /metrics always, traces and OTLP export when telemetry.otlpEndpoint is set.
	tel, err := telemetry.Setup(ctx, telemetry.Config{Version: version.Version, Target: r.cfg.Target, OTLPEndpoint: r.cfg.Telemetry.OTLPEndpoint})
	if err != nil {
		return fmt.Errorf("setting up telemetry: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(shutCtx)
	}()
	// 2. Initialize Ops server in background (:9090) with DB readiness probe
	if pgStore != nil {
		r.ops = telemetry.NewOpsServer(r.cfg.Server.OpsAddr, func(c context.Context) error {
			return pgStore.Pool().Ping(c)
		})
	}

	r.ops.SetMetricsHandler(tel.MetricsHandler())

	errOpsChan := make(chan error, 1)
	errOperatorChan := make(chan error, 1)
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

	// 3b. The operator (D1, D3): only in-cluster or with an explicit kubeconfig.
	if err := r.startOperator(ctx, storeBackend, sysStore, errOperatorChan); err != nil {
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

	isWebUI := isAll || contains(targetList, "web-ui")
	if !isWebUI {
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

	// Sign-in, sessions, ui-config and /me (doc 13 section 3, doc 14 section 2).
	if isAll || contains(targetList, "query-api") {
		h, err := r.buildAuthHandlers(storeBackend, authn)
		if err != nil {
			return err
		}
		h.RegisterRoutes(mux)
	}

	// The SPA owns every path the backend does not (deep links fall back to index.html).
	if isWebUI {
		r.logger.Info("serving the web UI on /")
		mux.Handle("/", ui.Handler(ui.Options{HSTS: strings.HasPrefix(r.cfg.Server.PublicURL, "https://")}))
	}

	httpServer := &http.Server{
		Addr:              r.cfg.Server.HTTPAddr,
		Handler:           telemetry.RequestIDMiddleware(telemetry.HTTPMiddleware(mux)),
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
	case err := <-errOperatorChan:
		return err
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

// buildAuthHandlers wires the browser auth endpoints. With no auth.oidc.issuer the endpoints still
// exist (ui-config reports no sign-in method) so the UI can say so instead of failing.
func (r *Runner) buildAuthHandlers(st store.Store, authn *auth.Authenticator) (*auth.Handlers, error) {
	tenants, ok := st.(auth.TenantLookup)
	if !ok {
		return nil, fmt.Errorf("the store cannot look up tenants by slug")
	}
	deps := auth.HandlerDeps{
		Identity: st, Tenants: tenants, Authn: authn, Logger: r.logger,
		Product: "Rampart", Version: version.Version,
	}
	oc := r.cfg.Auth.OIDC
	if oc.Issuer == "" {
		r.logger.Warn("auth.oidc.issuer is not set: browser sign-in is disabled (API tokens still work)")
		return auth.NewHandlers(deps), nil
	}

	key, err := readSecretFile(r.cfg.Auth.Session.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("auth.session.keyFile: %w", err)
	}
	var secret []byte
	if oc.ClientSecretFile != "" {
		if secret, err = readSecretFile(oc.ClientSecretFile); err != nil {
			return nil, fmt.Errorf("auth.oidc.clientSecretFile: %w", err)
		}
	}
	secure := strings.HasPrefix(r.cfg.Server.PublicURL, "https://")
	sessions, err := auth.NewSessionManager(st, auth.SessionConfig{
		Key: key, Secure: secure, Idle: r.cfg.Auth.Session.IdleTimeout, Absolute: r.cfg.Auth.Session.AbsoluteTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("auth.session.keyFile: %w", err)
	}
	authn.SetSessions(sessions)

	policy := auth.RolePolicy{DefaultRole: auth.Role(oc.DefaultRole)}
	for _, b := range oc.Bindings {
		policy.Bindings = append(policy.Bindings, auth.Binding{Kind: b.Kind, Name: b.Name, Role: auth.Role(b.Role)})
	}
	deps.Sessions = sessions
	deps.Policy = policy
	deps.OIDC = auth.NewOIDCClient(auth.OIDCConfig{
		Issuer: oc.Issuer, ClientID: oc.ClientID, ClientSecret: string(secret),
		RedirectURL: strings.TrimRight(r.cfg.Server.PublicURL, "/") + "/auth/oidc/default/callback",
		Scopes:      oc.Scopes, GroupsClaim: oc.GroupsClaim, RequireEmailVerified: oc.RequireEmailVerified,
	})
	r.logger.Info("browser sign-in enabled", "issuer", oc.Issuer, "redirect", strings.TrimRight(r.cfg.Server.PublicURL, "/")+"/auth/oidc/default/callback")
	return auth.NewHandlers(deps), nil
}

// readSecretFile reads a secret from a file, dropping trailing newlines only.
func readSecretFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

// operatorRESTConfig finds the cluster the operator reconciles. It returns (nil, "") when there is none.
// It deliberately ignores ~/.kube/config and $KUBECONFIG.
func (r *Runner) operatorRESTConfig() (*rest.Config, string, error) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		c, err := rest.InClusterConfig()
		return c, "in-cluster", err
	}
	if path := r.cfg.Operator.Kubeconfig; path != "" {
		c, err := clientcmd.BuildConfigFromFlags("", path)
		return c, "kubeconfig " + path, err
	}
	return nil, "", nil
}

func (r *Runner) startOperator(ctx context.Context, st store.Store, sys *store.PostgresStore, errCh chan<- error) error {
	mode := r.cfg.Operator.Mode
	if mode == "off" {
		return nil
	}
	rc, source, err := r.operatorRESTConfig()
	if err != nil {
		return fmt.Errorf("operator: loading cluster configuration from %s: %w", source, err)
	}
	if rc == nil {
		if mode == "on" {
			return fmt.Errorf("operator.mode=on but there is no in-cluster configuration and no --kubeconfig")
		}
		r.logger.Info("operator not started: not in a cluster and no --kubeconfig (operator.mode=auto)")
		return nil
	}
	if sys == nil {
		return fmt.Errorf("the operator writes configuration as rampart_system: set database.systemUrl")
	}
	configStore, ok := store.Store(sys).(apply.ConfigStore)
	if !ok {
		return fmt.Errorf("the system store cannot hold configuration")
	}

	var secretStore operator.SecretMaterialStore
	if key, kerr := readSecretFile(r.cfg.Auth.Session.KeyFile); kerr == nil {
		cipher, cerr := secrets.NewCipher(key)
		if cerr != nil {
			return fmt.Errorf("auth.session.keyFile: %w", cerr)
		}
		secretStore = &operator.EncryptingSecretStore{Inner: sys, Cipher: cipher}
	} else {
		r.logger.Warn("auth.session.keyFile is not set or unreadable: Secrets referenced by ScanSources will not be synced", "err", kerr)
	}

	ns := firstNonEmpty(r.cfg.Operator.Namespace, os.Getenv("POD_NAMESPACE"))
	r.logger.Info("operator starting", "cluster", source, "leaderElectionNamespace", ns)
	go func() {
		errCh <- operator.Run(ctx, operator.ManagerConfig{
			REST: rc, Store: configStore, SecretStore: secretStore, Logger: r.logger,
			LeaderElectionNamespace: ns, SecretReaderClusterRole: r.cfg.Operator.SecretReaderClusterRole,
			ServiceAccountName: r.cfg.Operator.ServiceAccount, ServiceAccountNamespace: ns,
		})
	}()
	return nil
}
