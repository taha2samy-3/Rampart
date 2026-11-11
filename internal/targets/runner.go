package targets

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"rampart/internal/config"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/query"
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

	// 1. Start Ops server in background (:9090)
	errOpsChan := make(chan error, 1)
	go func() {
		if err := r.ops.Start(); err != nil && err != http.ErrServerClosed {
			errOpsChan <- fmt.Errorf("ops server error: %w", err)
		}
	}()

	// 2. Parse selected targets
	targetList := strings.Split(r.cfg.Target, ",")
	isAll := false
	for _, t := range targetList {
		if strings.TrimSpace(t) == "all" {
			isAll = true
			break
		}
	}

	// 3. Initialize HTTP multiplexer for server.http.addr (:8080)
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

	queue := jobs.NewInMemJobQueue()
	store := ingest.NewMemoryStore()
	feeds := enrich.NewFeedStore()
	registry := integrations.DefaultRegistry()

	gw := ingest.NewGatewayWithDeps(queue, store, registry, feeds)
	queryAPI := query.NewAPI(store, feeds)

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
