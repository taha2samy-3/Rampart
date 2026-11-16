package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rampart/internal/telemetry"
)

func TestSetupLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := telemetry.SetupLogger("info", "json", buf)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	logger.Info("system booted", "target", "all")
	out := buf.String()
	if !strings.Contains(out, "system booted") || !strings.Contains(out, `"target":"all"`) {
		t.Errorf("unexpected log output format: %s", out)
	}
}

func TestOpsServerEndpoints(t *testing.T) {
	// 1. Healthz
	ops := telemetry.NewOpsServer(":0")
	reqHealth := httptest.NewRequest("GET", "/healthz", nil)
	recHealth := httptest.NewRecorder()
	ops.Handler().ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("healthz returned %d, want 200", recHealth.Code)
	}
	if !strings.Contains(recHealth.Body.String(), "ok") {
		t.Errorf("healthz body = %q, want 'ok'", recHealth.Body.String())
	}

	// 2. Readyz with passing checker
	opsReady := telemetry.NewOpsServer(":0", func(ctx context.Context) error {
		return nil
	})
	readyz := func(o *telemetry.OpsServer) int {
		rec := httptest.NewRecorder()
		o.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		return rec.Code
	}
	// The server was "ready" from the moment it was built, while migrations and bootstrap still ran, so a
	// rolling update sent traffic to a pod that could not answer yet. It is ready when the runner says so.
	if got := readyz(opsReady); got != http.StatusServiceUnavailable {
		t.Errorf("readyz before SetReady returned %d, want 503", got)
	}
	opsReady.SetReady(true)
	if got := readyz(opsReady); got != http.StatusOK {
		t.Errorf("readyz returned %d, want 200", got)
	}
	opsReady.SetReady(false)
	if got := readyz(opsReady); got != http.StatusServiceUnavailable {
		t.Errorf("readyz after SetReady(false) returned %d, want 503", got)
	}

	// 3. Readyz with failing checker
	opsFailing := telemetry.NewOpsServer(":0", func(ctx context.Context) error {
		return errors.New("db disconnected")
	})
	opsFailing.SetReady(true)
	reqFailing := httptest.NewRequest("GET", "/readyz", nil)
	recFailing := httptest.NewRecorder()
	opsFailing.Handler().ServeHTTP(recFailing, reqFailing)
	if recFailing.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", recFailing.Code)
	}

	// 4. Metrics endpoint
	reqMetrics := httptest.NewRequest("GET", "/metrics", nil)
	recMetrics := httptest.NewRecorder()
	ops.Handler().ServeHTTP(recMetrics, reqMetrics)
	if recMetrics.Code != http.StatusOK {
		t.Errorf("metrics returned %d, want 200", recMetrics.Code)
	}
	if !strings.Contains(recMetrics.Body.String(), "rampart_uptime_seconds") {
		t.Errorf("metrics body = %q, want rampart_uptime_seconds", recMetrics.Body.String())
	}
}
