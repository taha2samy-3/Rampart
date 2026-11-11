package config_test

import (
	"testing"

	"rampart/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Target != "all" {
		t.Errorf("expected default target 'all', got %q", cfg.Target)
	}
	if cfg.Server.HTTPAddr != ":8080" {
		t.Errorf("expected HTTP addr ':8080', got %q", cfg.Server.HTTPAddr)
	}
	if cfg.Server.OpsAddr != ":9090" {
		t.Errorf("expected Ops addr ':9090', got %q", cfg.Server.OpsAddr)
	}
	if cfg.Ingest.BatchRows != 5000 {
		t.Errorf("expected batch rows 5000, got %d", cfg.Ingest.BatchRows)
	}
	if cfg.Ingest.MaxReportBytes != 536870912 {
		t.Errorf("expected 512MB (536870912 bytes), got %d", cfg.Ingest.MaxReportBytes)
	}
	if cfg.Operator.Mode != "auto" {
		t.Errorf("expected operator mode 'auto', got %q", cfg.Operator.Mode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
}

func TestLoadWithFlags(t *testing.T) {
	args := []string{
		"-target=ingest-gateway",
		"-http-addr=:8000",
		"-ops-addr=:9000",
		"-log-level=debug",
		"-log-format=text",
		"-operator=on",
	}

	cfg, err := config.Load(args)
	if err != nil {
		t.Fatalf("failed to load config with flags: %v", err)
	}

	if cfg.Target != "ingest-gateway" {
		t.Errorf("expected target 'ingest-gateway', got %q", cfg.Target)
	}
	if cfg.Server.HTTPAddr != ":8000" {
		t.Errorf("expected HTTP addr ':8000', got %q", cfg.Server.HTTPAddr)
	}
	if cfg.Server.OpsAddr != ":9000" {
		t.Errorf("expected Ops addr ':9000', got %q", cfg.Server.OpsAddr)
	}
	if cfg.Telemetry.LogLevel != "debug" {
		t.Errorf("expected log level 'debug', got %q", cfg.Telemetry.LogLevel)
	}
	if cfg.Telemetry.LogFormat != "text" {
		t.Errorf("expected log format 'text', got %q", cfg.Telemetry.LogFormat)
	}
	if cfg.Operator.Mode != "on" {
		t.Errorf("expected operator mode 'on', got %q", cfg.Operator.Mode)
	}
}

func TestLoadWithEnv(t *testing.T) {
	t.Setenv("RAMPART_TARGET", "parser")
	t.Setenv("RAMPART_SERVER_HTTP_ADDR", ":8088")
	t.Setenv("RAMPART_INGEST_BATCH_ROWS", "2500")

	cfg, err := config.Load([]string{})
	if err != nil {
		t.Fatalf("failed to load config with env: %v", err)
	}

	if cfg.Target != "parser" {
		t.Errorf("expected target 'parser', got %q", cfg.Target)
	}
	if cfg.Server.HTTPAddr != ":8088" {
		t.Errorf("expected HTTP addr ':8088', got %q", cfg.Server.HTTPAddr)
	}
	if cfg.Ingest.BatchRows != 2500 {
		t.Errorf("expected batch rows 2500, got %d", cfg.Ingest.BatchRows)
	}
}
