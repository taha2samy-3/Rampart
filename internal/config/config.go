package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete runtime configuration tree (normative D6).
type Config struct {
	Target        string              `json:"target" yaml:"target"`
	Server        ServerConfig        `json:"server" yaml:"server"`
	Database      DatabaseConfig      `json:"database" yaml:"database"`
	ObjectStorage ObjectStorageConfig `json:"object_storage" yaml:"object_storage"`
	Ingest        IngestConfig        `json:"ingest" yaml:"ingest"`
	Telemetry     TelemetryConfig     `json:"telemetry" yaml:"telemetry"`
	Operator      OperatorConfig      `json:"operator" yaml:"operator"`
	Auth          AuthConfig          `json:"auth" yaml:"auth"`
}

// AuthConfig holds authentication settings (D6, D3).
type AuthConfig struct {
	// BootstrapAdminTokenFile is where the first admin API token is written (0600) when it
	// does not exist yet. It replaces logging the token: a secret in logs is a leak (D3).
	BootstrapAdminTokenFile string `json:"bootstrap_admin_token_file" yaml:"bootstrap_admin_token_file"`
}

type ServerConfig struct {
	HTTPAddr  string `json:"http_addr" yaml:"http_addr"`
	OpsAddr   string `json:"ops_addr" yaml:"ops_addr"`
	PublicURL string `json:"public_url" yaml:"public_url"`
}

type DatabaseConfig struct {
	URL       string `json:"url" yaml:"url"`
	DirectURL string `json:"direct_url" yaml:"direct_url"`
	// MigrateURL connects as rampart_owner and is used only by migrations (D4).
	MigrateURL string `json:"migrate_url" yaml:"migrate_url"`
	// SystemURL connects as rampart_system (BYPASSRLS): tenant bootstrap, feeds, maintenance (D4).
	SystemURL   string `json:"system_url" yaml:"system_url"`
	ReadURL     string `json:"read_url" yaml:"read_url"`
	AutoMigrate bool   `json:"auto_migrate" yaml:"auto_migrate"`
}

type ObjectStorageConfig struct {
	Endpoint         string `json:"endpoint" yaml:"endpoint"`
	ExternalEndpoint string `json:"external_endpoint" yaml:"external_endpoint"`
	Region           string `json:"region" yaml:"region"`
	BucketRaw        string `json:"bucket_raw" yaml:"bucket_raw"`
	BucketExports    string `json:"bucket_exports" yaml:"bucket_exports"`
	AccessKeyFile    string `json:"access_key_file" yaml:"access_key_file"`
	SecretKeyFile    string `json:"secret_key_file" yaml:"secret_key_file"`
	UsePathStyle     bool   `json:"use_path_style" yaml:"use_path_style"`
}

type IngestConfig struct {
	MaxReportBytes int64 `json:"max_report_bytes" yaml:"max_report_bytes"`
	BatchRows      int   `json:"batch_rows" yaml:"batch_rows"`
}

type TelemetryConfig struct {
	OTLPEndpoint string `json:"otlp_endpoint" yaml:"otlp_endpoint"`
	LogLevel     string `json:"log_level" yaml:"log_level"`
	LogFormat    string `json:"log_format" yaml:"log_format"`
}

type OperatorConfig struct {
	Mode string `json:"mode" yaml:"mode"` // auto | on | off (D6)
}

// DefaultConfig provides standard normative defaults.
func DefaultConfig() *Config {
	return &Config{
		Target: "all",
		Server: ServerConfig{
			HTTPAddr: ":8080",
			OpsAddr:  ":9090", // Ops port per D6 (never exposed externally)
		},
		Database: DatabaseConfig{
			URL:         "",
			DirectURL:   "",
			AutoMigrate: true,
		},
		ObjectStorage: ObjectStorageConfig{
			BucketRaw:     "rampart-raw-reports",
			BucketExports: "rampart-exports",
			Region:        "us-east-1",
			UsePathStyle:  true,
		},
		Ingest: IngestConfig{
			MaxReportBytes: 536870912, // 512 MiB per D6
			BatchRows:      5000,      // 5 000 rows per transaction per D2
		},
		Telemetry: TelemetryConfig{
			LogLevel:  "info",
			LogFormat: "json",
		},
		Operator: OperatorConfig{
			Mode: "auto",
		},
	}
}

// Load loads configuration with precedence: Flags > Environment Variables > Config File > Defaults (D6).
func Load(args []string) (*Config, error) {
	cfg := DefaultConfig()

	// 1. Load config file (/etc/rampart/config.yaml or RAMPART_CONFIG_FILE)
	loadConfigFile(cfg)

	// 2. Apply environment variables
	applyEnv(cfg)

	// 3. Parse command-line flags
	fs := flag.NewFlagSet("rampart", flag.ContinueOnError)

	targetFlag := fs.String("target", cfg.Target, "Target component: all, ingest-gateway, parser, enrich, policy, notify, sync, query-api, operator, scheduler")
	httpAddrFlag := fs.String("http-addr", cfg.Server.HTTPAddr, "HTTP listener address (:8080)")
	opsAddrFlag := fs.String("ops-addr", cfg.Server.OpsAddr, "Ops listener address (:9090 for :healthz, :readyz, :metrics)")
	dbURLFlag := fs.String("db-url", cfg.Database.URL, "PostgreSQL pooled URL")
	dbDirectURLFlag := fs.String("db-direct-url", cfg.Database.DirectURL, "PostgreSQL direct URL for River/NOTIFY")
	dbMigrateURLFlag := fs.String("db-migrate-url", cfg.Database.MigrateURL, "PostgreSQL URL of rampart_owner, used only for migrations")
	dbSystemURLFlag := fs.String("db-system-url", cfg.Database.SystemURL, "PostgreSQL URL of rampart_system, used for tenant bootstrap and maintenance")
	logLevelFlag := fs.String("log-level", cfg.Telemetry.LogLevel, "Log level: debug, info, warn, error")
	logFormatFlag := fs.String("log-format", cfg.Telemetry.LogFormat, "Log format: json or text")
	operatorModeFlag := fs.String("operator", cfg.Operator.Mode, "Operator mode: auto, on, off")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil, flag.ErrHelp
		}
		return nil, fmt.Errorf("config: parsing flags failed: %w", err)
	}

	if *targetFlag != "" {
		cfg.Target = *targetFlag
	}
	if *httpAddrFlag != "" {
		cfg.Server.HTTPAddr = *httpAddrFlag
	}
	if *opsAddrFlag != "" {
		cfg.Server.OpsAddr = *opsAddrFlag
	}
	if *dbURLFlag != "" {
		cfg.Database.URL = *dbURLFlag
	}
	if *dbDirectURLFlag != "" {
		cfg.Database.DirectURL = *dbDirectURLFlag
	}
	if *dbMigrateURLFlag != "" {
		cfg.Database.MigrateURL = *dbMigrateURLFlag
	}
	if *dbSystemURLFlag != "" {
		cfg.Database.SystemURL = *dbSystemURLFlag
	}
	if *logLevelFlag != "" {
		cfg.Telemetry.LogLevel = *logLevelFlag
	}
	if *logFormatFlag != "" {
		cfg.Telemetry.LogFormat = *logFormatFlag
	}
	if *operatorModeFlag != "" {
		cfg.Operator.Mode = *operatorModeFlag
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

var validTargets = map[string]bool{
	"all":            true,
	"ingest-gateway": true,
	"parser":         true,
	"enrich":         true,
	"policy":         true,
	"notify":         true,
	"sync":           true,
	"query-api":      true,
	"operator":       true,
	"scheduler":      true,
	"web-ui":         true,
}

// Validate checks configuration sanity.
func (c *Config) Validate() error {
	if c.Target == "" {
		return fmt.Errorf("config: target cannot be empty")
	}

	for _, item := range strings.Split(c.Target, ",") {
		targetName := strings.TrimSpace(item)
		if targetName != "" && !validTargets[targetName] {
			return fmt.Errorf("config: invalid target %q", targetName)
		}
	}

	if c.Server.HTTPAddr == "" {
		return fmt.Errorf("config: server.http.addr cannot be empty")
	}
	if c.Server.OpsAddr == "" {
		return fmt.Errorf("config: server.ops.addr cannot be empty")
	}
	if c.Ingest.BatchRows <= 0 {
		return fmt.Errorf("config: ingest.batch_rows must be greater than zero")
	}
	if c.Ingest.MaxReportBytes <= 0 {
		return fmt.Errorf("config: ingest.max_report_bytes must be greater than zero")
	}
	return nil
}

func loadConfigFile(cfg *Config) {
	filePath := "/etc/rampart/config.yaml"
	if envPath := os.Getenv("RAMPART_CONFIG_FILE"); envPath != "" {
		filePath = envPath
	}

	data, err := os.ReadFile(filePath)
	if err == nil {
		_ = yaml.Unmarshal(data, cfg)
	}
}

func applyEnv(cfg *Config) {
	get := func(key string) string {
		return os.Getenv("RAMPART_" + key)
	}

	if v := get("TARGET"); v != "" {
		cfg.Target = v
	}
	if v := get("SERVER_HTTP_ADDR"); v != "" {
		cfg.Server.HTTPAddr = v
	}
	if v := get("SERVER_OPS_ADDR"); v != "" {
		cfg.Server.OpsAddr = v
	}
	if v := get("SERVER_PUBLIC_URL"); v != "" {
		cfg.Server.PublicURL = v
	}
	if v := get("DATABASE_URL"); v != "" {
		cfg.Database.URL = v
	}
	if v := get("DATABASE_DIRECT_URL"); v != "" {
		cfg.Database.DirectURL = v
	}
	if v := get("DATABASE_MIGRATE_URL"); v != "" {
		cfg.Database.MigrateURL = v
	}
	if v := get("DATABASE_SYSTEM_URL"); v != "" {
		cfg.Database.SystemURL = v
	}
	if v := get("AUTH_BOOTSTRAP_ADMIN_TOKEN_FILE"); v != "" {
		cfg.Auth.BootstrapAdminTokenFile = v
	}
	if v := get("DATABASE_READ_URL"); v != "" {
		cfg.Database.ReadURL = v
	}
	if v := get("DATABASE_AUTO_MIGRATE"); v != "" {
		cfg.Database.AutoMigrate = strings.ToLower(v) == "true" || v == "1"
	}
	if v := get("OBJECT_STORAGE_ENDPOINT"); v != "" {
		cfg.ObjectStorage.Endpoint = v
	}
	if v := get("OBJECT_STORAGE_BUCKET_RAW"); v != "" {
		cfg.ObjectStorage.BucketRaw = v
	}
	if v := get("INGEST_MAX_REPORT_BYTES"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.Ingest.MaxReportBytes = val
		}
	}
	if v := get("INGEST_BATCH_ROWS"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.Ingest.BatchRows = val
		}
	}
	// Support both RAMPART_LOG_LEVEL and RAMPART_TELEMETRY_LOG_LEVEL
	if v := get("LOG_LEVEL"); v != "" {
		cfg.Telemetry.LogLevel = v
	}
	if v := get("TELEMETRY_LOG_LEVEL"); v != "" {
		cfg.Telemetry.LogLevel = v
	}
	if v := get("LOG_FORMAT"); v != "" {
		cfg.Telemetry.LogFormat = v
	}
	if v := get("TELEMETRY_LOG_FORMAT"); v != "" {
		cfg.Telemetry.LogFormat = v
	}
	if v := get("OPERATOR_MODE"); v != "" {
		cfg.Operator.Mode = v
	}
}
