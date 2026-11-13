package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// D6: the file uses the documented keys (server.http.addr, database.directUrl, auth.oidc.*).
func TestConfigFileFollowsD6Shape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `
server:
  http: {addr: ":18080"}
  ops: {addr: ":19090"}
  publicUrl: https://rampart.example.com
database:
  directUrl: postgres://direct
  migrateUrl: postgres://owner
auth:
  session: {keyFile: /run/secrets/session, idleTimeout: 2h}
  oidc:
    issuer: https://idp.example.com
    clientId: rampart
    clientSecretFile: /run/secrets/oidc
    defaultRole: triager
    bindings:
      - {kind: group, name: sec-admins, role: admin}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAMPART_CONFIG_FILE", path)
	cfg, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.HTTPAddr != ":18080" || cfg.Server.OpsAddr != ":19090" || cfg.Server.PublicURL != "https://rampart.example.com" {
		t.Errorf("server: %+v", cfg.Server)
	}
	if cfg.Database.DirectURL != "postgres://direct" || cfg.Database.MigrateURL != "postgres://owner" {
		t.Errorf("database: %+v", cfg.Database)
	}
	o := cfg.Auth.OIDC
	if o.Issuer != "https://idp.example.com" || o.DefaultRole != "triager" || len(o.Bindings) != 1 || o.Bindings[0].Role != "admin" {
		t.Errorf("oidc: %+v", o)
	}
	if cfg.Auth.Session.IdleTimeout != 2*time.Hour || cfg.Auth.Session.AbsoluteTimeout != 24*time.Hour {
		t.Errorf("session: %+v (absolute must keep its 24h default)", cfg.Auth.Session)
	}
	// env beats file
	t.Setenv("RAMPART_AUTH_OIDC_DEFAULT_ROLE", "viewer")
	t.Setenv("RAMPART_AUTH_OIDC_BINDINGS", "user:alice@example.com=admin,group:devs=triager")
	cfg, _ = config.Load(nil)
	if cfg.Auth.OIDC.DefaultRole != "viewer" || len(cfg.Auth.OIDC.Bindings) != 2 || cfg.Auth.OIDC.Bindings[0].Name != "alice@example.com" {
		t.Errorf("env must override the file: %+v", cfg.Auth.OIDC)
	}
}

func TestOIDCNeedsSessionKeyAndPublicURL(t *testing.T) {
	t.Setenv("RAMPART_CONFIG_FILE", filepath.Join(t.TempDir(), "none.yaml"))
	t.Setenv("RAMPART_AUTH_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("RAMPART_AUTH_OIDC_CLIENT_ID", "rampart")
	if _, err := config.Load(nil); err == nil {
		t.Fatal("an issuer without a session key and a public URL must be refused")
	}
	t.Setenv("RAMPART_AUTH_SESSION_KEY_FILE", "/k")
	t.Setenv("RAMPART_SERVER_PUBLIC_URL", "https://rampart.example.com")
	if _, err := config.Load(nil); err != nil {
		t.Fatalf("complete OIDC settings must load: %v", err)
	}
	t.Setenv("RAMPART_AUTH_OIDC_DEFAULT_ROLE", "superuser")
	if _, err := config.Load(nil); err == nil {
		t.Fatal("an unknown default role must be refused")
	}
}

func TestConnectorsSSRFAllowlistConfig(t *testing.T) {
	// 1. Wildcard '*' in hosts must be rejected
	c := config.SSRFAllowlistConfig{
		Hosts: []string{"*"},
	}
	if _, err := c.ToPlatformSSRFAllowlist(); err == nil {
		t.Fatal("expected wildcard '*' in SSRF allowlist to be rejected, got nil")
	}

	// 2. Invalid CIDR must be rejected
	cInvalidCIDR := config.SSRFAllowlistConfig{
		CIDRs: []string{"not-a-cidr"},
	}
	if _, err := cInvalidCIDR.ToPlatformSSRFAllowlist(); err == nil {
		t.Fatal("expected invalid CIDR to be rejected, got nil")
	}

	// 3. Valid CIDR and host converts properly
	cValid := config.SSRFAllowlistConfig{
		CIDRs:             []string{"10.96.0.0/12"},
		Hosts:             []string{"dtrack.dtrack.svc"},
		AllowInternalHTTP: true,
	}
	al, err := cValid.ToPlatformSSRFAllowlist()
	if err != nil {
		t.Fatalf("expected valid config to succeed, got: %v", err)
	}
	if len(al.AllowedCIDRs) != 1 || len(al.AllowedHosts) != 1 || !al.AllowInternalHTTP {
		t.Errorf("unexpected allowlist fields: %+v", al)
	}
}
