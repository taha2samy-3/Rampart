package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// ReadinessChecker checks if a subsystem is ready.
type ReadinessChecker func(ctx context.Context) error

// OpsServer runs the internal operations endpoints on its own dedicated port (D6).
// It serves /healthz, /readyz, and /metrics.
type OpsServer struct {
	server    *http.Server
	ready     atomic.Bool
	checkers  []ReadinessChecker
	startTime time.Time
}

// NewOpsServer creates an OpsServer bound to the specified address (default :9090).
func NewOpsServer(addr string, checkers ...ReadinessChecker) *OpsServer {
	ops := &OpsServer{
		checkers:  checkers,
		startTime: time.Now(),
	}
	ops.ready.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", ops.handleHealthz)
	mux.HandleFunc("/readyz", ops.handleReadyz)
	mux.HandleFunc("/metrics", ops.handleMetrics)

	ops.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return ops
}

// Handler returns the underlying HTTP handler (useful for testing).
func (s *OpsServer) Handler() http.Handler {
	return s.server.Handler
}

// Start runs the HTTP listener synchronously until closed.
func (s *OpsServer) Start() error {
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("ops server failed: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the ops server.
func (s *OpsServer) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	return s.server.Shutdown(ctx)
}

// SetReady updates the internal readiness flag.
func (s *OpsServer) SetReady(ready bool) {
	s.ready.Store(ready)
}

func (s *OpsServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *OpsServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	for _, check := range s.checkers {
		if err := check(ctx); err != nil {
			http.Error(w, fmt.Sprintf("unready: %v", err), http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *OpsServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	uptime := time.Since(s.startTime).Seconds()
	_, _ = fmt.Fprintf(w, "# HELP rampart_uptime_seconds Process uptime\n# TYPE rampart_uptime_seconds gauge\nrampart_uptime_seconds %.2f\n", uptime)
}
