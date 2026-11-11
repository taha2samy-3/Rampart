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
	reqReady := httptest.NewRequest("GET", "/readyz", nil)
	recReady := httptest.NewRecorder()
	opsReady.Handler().ServeHTTP(recReady, reqReady)
	if recReady.Code != http.StatusOK {
		t.Errorf("readyz returned %d, want 200", recReady.Code)
	}

	// 3. Readyz with failing checker
	opsFailing := telemetry.NewOpsServer(":0", func(ctx context.Context) error {
		return errors.New("db disconnected")
	})
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
