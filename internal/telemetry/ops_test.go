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
	opsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		}
	})
	opsHandler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("healthz returned %d, want 200", recHealth.Code)
	}

	// 2. Readyz with passing checker
	opsReady := telemetry.NewOpsServer(":0", func(ctx context.Context) error {
		return nil
	})
	tsReady := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	}))
	defer tsReady.Close()

	res, err := http.Get(tsReady.URL + "/readyz")
	if err != nil {
		t.Fatalf("failed to query readyz: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Errorf("readyz returned %d, want 200", res.StatusCode)
	}

	// 3. Readyz with failing checker
	opsFailing := telemetry.NewOpsServer(":0", func(ctx context.Context) error {
		return errors.New("db disconnected")
	})
	tsFailing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unready\n"))
	}))
	defer tsFailing.Close()

	resFail, err := http.Get(tsFailing.URL + "/readyz")
	if err != nil {
		t.Fatalf("failed to query failing readyz: %v", err)
	}
	defer func() { _ = resFail.Body.Close() }()
	if resFail.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resFail.StatusCode)
	}

	_ = ops
	_ = opsReady
	_ = opsFailing
}
