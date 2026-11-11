package targets_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"rampart/internal/config"
	"rampart/internal/targets"
)

func TestRunnerLifecycle(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.HTTPAddr = "127.0.0.1:0" // Pick free port
	cfg.Server.OpsAddr = "127.0.0.1:0"  // Pick free port
	cfg.Target = "all"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := targets.NewRunner(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())

	runErrChan := make(chan error, 1)
	go func() {
		runErrChan <- runner.Run(ctx)
	}()

	// Give servers a brief moment to bind and listen
	time.Sleep(100 * time.Millisecond)

	// Trigger cancellation for graceful teardown
	cancel()

	select {
	case err := <-runErrChan:
		if err != nil {
			t.Fatalf("runner returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for runner to shut down gracefully")
	}
}

var _ = http.StatusOK
