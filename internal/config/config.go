package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete runtime configuration tree (normative D6).
type Config struct {
	Target        string              `json:"target" yaml:"target"`
	Server        ServerConfig        `json:"server" yaml:"server"`
	Database      DatabaseConfig      `json:"database" yaml:"database"`
	ObjectStorage ObjectStorageConfig `json:"object_storage" yaml:"objectStorage"`
	Ingest        IngestConfig        `json:"ingest" yaml:"ingest"`
	Telemetry     TelemetryConfig     `json:"telemetry" yaml:"telemetry"`
	Operator      OperatorConfig      `json:"operator" yaml:"operator"`
	Auth          AuthConfig          `json:"auth" yaml:"auth"`
}

// AuthConfig holds authentication settings (D6, D3, D8).
type AuthConfig struct {
	OIDC    OIDCSettings    `json:"oidc" yaml:"oidc"`
	Session SessionSettings `json:"session" yaml:"session"`
	// BootstrapAdmin is the break-glass local administrator (D3, doc 14 section 1).
	BootstrapAdmin BootstrapAdminSettings `json:"bootstrap_admin" yaml:"bootstrapAdmin"`

	// BootstrapAdminTokenFile is where the first admin API token is written (0600) when it
	// does not exist yet. It replaces logging the token: a secret in logs is a leak (D3).
	BootstrapAdminTokenFile string `json:"bootstrap_admin_token_file" yaml:"bootstrapAdminTokenFile"`
}

// BootstrapAdminSettings configures the first local administrator, like Argo CD's initial admin.
// It is created once, at first boot, from the password in PasswordFile; if the file does not exist a
// random password is generated into it (0600). Sign-in with it is refused once an identity provider is
// configured unless KeepEnabled is set. Every use is audited and logged as a warning.
type BootstrapAdminSettings struct {
	Username     string `json:"username" yaml:"username"`
	PasswordFile string `json:"password_file" yaml:"passwordFile"`
	Tenant       string `json:"tenant" yaml:"tenant"`
	KeepEnabled  bool   `json:"keep_enabled" yaml:"keepEnabled"`
}

// OIDCSettings is the static identity provider of Phase 1 (D6 auth.oidc.*, D8).
type OIDCSettings struct {
	Issuer           string   `json:"issuer" yaml:"issuer"`
	ClientID         string   `json:"client_id" yaml:"clientId"`
	ClientSecretFile string   `json:"client_secret_file" yaml:"clientSecretFile"`
	Scopes           []string `json:"scopes" yaml:"scopes"`
	GroupsClaim      string   `json:"groups_claim" yaml:"groupsClaim"`
	// RequireEmailVerified refuses logins whose email the IdP does not vouch for (doc 14 section 3).
	RequireEmailVerified bool `json:"require_email_verified" yaml:"requireEmailVerified"`
	// DefaultRole is given on first login when no binding matches: viewer, triager, admin, or empty for no access.
	DefaultRole string `json:"default_role" yaml:"defaultRole"`
	// Bindings grant roles to a person (kind user: email or subject) or a group at tenant scope.
	// They are the Phase 1 form of an AccessBinding; roles are never read straight from the IdP.
	Bindings []BindingSetting `json:"bindings" yaml:"bindings"`
}

// BindingSetting is one role binding (see OIDCSettings.Bindings).
type BindingSetting struct {
	Kind string `json:"kind" yaml:"kind"` // user | group
	Name string `json:"name" yaml:"name"`
	Role string `json:"role" yaml:"role"`
}

// SessionSettings configures browser sessions (doc 14 section 2).
type SessionSettings struct {
	// KeyFile holds a 32-byte key that signs CSRF tokens and seals the login state (D6 auth.session.keyFile).
	KeyFile         string        `json:"key_file" yaml:"keyFile"`
	IdleTimeout     time.Duration `json:"idle_timeout" yaml:"idleTimeout"`
	AbsoluteTimeout time.Duration `json:"absolute_timeout" yaml:"absoluteTimeout"`
}

// UnmarshalYAML reads the D6 shape: server.http.addr, server.ops.addr, server.publicUrl.
func (s *ServerConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		HTTP struct {
			Addr string `yaml:"addr"`
		} `yaml:"http"`
		Ops struct {
			Addr string `yaml:"addr"`
		} `yaml:"ops"`
		PublicURL string `yaml:"publicUrl"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if raw.HTTP.Addr != "" {
		s.HTTPAddr = raw.HTTP.Addr
	}
	if raw.Ops.Addr != "" {
		s.OpsAddr = raw.Ops.Addr
	}
	if raw.PublicURL != "" {
		s.PublicURL = raw.PublicURL
	}
	return nil
}

type ServerConfig struct {
	HTTPAddr  string `json:"http_addr" yaml:"httpAddr"`
	OpsAddr   string `json:"ops_addr" yaml:"opsAddr"`
	PublicURL string `json:"public_url" yaml:"publicUrl"`
}

type DatabaseConfig struct {
	URL       string `json:"url" yaml:"url"`
	DirectURL string `json:"direct_url" yaml:"directUrl"`
	// MigrateURL connects as rampart_owner and is used only by migrations (D4).
	MigrateURL string `json:"migrate_url" yaml:"migrateUrl"`
	// SystemURL connects as rampart_system (BYPASSRLS): tenant bootstrap, feeds, maintenance (D4).
	SystemURL   string `json:"system_url" yaml:"systemUrl"`
	ReadURL     string `json:"read_url" yaml:"readUrl"`
	AutoMigrate bool   `json:"auto_migrate" yaml:"autoMigrate"`
}

type ObjectStorageConfig struct {
	Endpoint         string `json:"endpoint" yaml:"endpoint"`
	ExternalEndpoint string `json:"external_endpoint" yaml:"externalEndpoint"`
	Region           string `json:"region" yaml:"region"`
	BucketRaw        string `json:"bucket_raw" yaml:"bucketRaw"`
	BucketExports    string `json:"bucket_exports" yaml:"bucketExports"`
	AccessKeyFile    string `json:"access_key_file" yaml:"accessKeyFile"`
	SecretKeyFile    string `json:"secret_key_file" yaml:"secretKeyFile"`
	UsePathStyle     bool   `json:"use_path_style" yaml:"usePathStyle"`
}

type IngestConfig struct {
	MaxReportBytes int64 `json:"max_report_bytes" yaml:"maxReportBytes"`
	BatchRows      int   `json:"batch_rows" yaml:"batchRows"`
}

type TelemetryConfig struct {
	OTLPEndpoint string `json:"otlp_endpoint" yaml:"otlpEndpoint"`
	LogLevel     string `json:"log_level" yaml:"logLevel"`
	LogFormat    string `json:"log_format" yaml:"logFormat"`
}

type OperatorConfig struct {
	Mode string `json:"mode" yaml:"mode"` // auto | on | off (D6)
	// Kubeconfig is an explicit kubeconfig file. In "auto" mode the operator starts only in-cluster
	// or with this set; it never reads ~/.kube/config or $KUBECONFIG, so a developer laptop never
	// starts reconciling a real cluster by accident (D3).
	Kubeconfig string `json:"kubeconfig" yaml:"kubeconfig"`
	// ServiceAccount, Namespace and SecretReaderClusterRole describe the operator's own identity for
	// the per-tenant secret-reader binding (D1). Namespace also holds the leader-election Lease.
	ServiceAccount          string `json:"service_account" yaml:"serviceAccount"`
	Namespace               string `json:"namespace" yaml:"namespace"`
	SecretReaderClusterRole string `json:"secret_reader_cluster_role" yaml:"secretReaderClusterRole"`
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
		Auth: AuthConfig{
			OIDC:           OIDCSettings{RequireEmailVerified: true, DefaultRole: "viewer", GroupsClaim: "groups"},
			Session:        SessionSettings{IdleTimeout: 8 * time.Hour, AbsoluteTimeout: 24 * time.Hour},
			BootstrapAdmin: BootstrapAdminSettings{Username: "admin", Tenant: "default"},
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
	kubeconfigFlag := fs.String("kubeconfig", cfg.Operator.Kubeconfig, "Explicit kubeconfig for the operator (never read implicitly)")

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
	if *kubeconfigFlag != "" {
		cfg.Operator.Kubeconfig = *kubeconfigFlag
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
	if err := c.Auth.validate(c.Server.PublicURL); err != nil {
		return err
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
	if v := get("AUTH_OIDC_ISSUER"); v != "" {
		cfg.Auth.OIDC.Issuer = v
	}
	if v := get("AUTH_OIDC_CLIENT_ID"); v != "" {
		cfg.Auth.OIDC.ClientID = v
	}
	if v := get("AUTH_OIDC_CLIENT_SECRET_FILE"); v != "" {
		cfg.Auth.OIDC.ClientSecretFile = v
	}
	if v := get("AUTH_OIDC_SCOPES"); v != "" {
		cfg.Auth.OIDC.Scopes = splitList(v)
	}
	if v := get("AUTH_OIDC_GROUPS_CLAIM"); v != "" {
		cfg.Auth.OIDC.GroupsClaim = v
	}
	if v := get("AUTH_OIDC_DEFAULT_ROLE"); v != "" {
		cfg.Auth.OIDC.DefaultRole = v
	}
	if v := get("AUTH_OIDC_REQUIRE_EMAIL_VERIFIED"); v != "" {
		cfg.Auth.OIDC.RequireEmailVerified = strings.ToLower(v) == "true" || v == "1"
	}
	if v := get("AUTH_OIDC_BINDINGS"); v != "" { // user:alice@example.com=admin,group:sec=triager
		cfg.Auth.OIDC.Bindings = parseBindings(v)
	}
	if v := get("AUTH_SESSION_KEY_FILE"); v != "" {
		cfg.Auth.Session.KeyFile = v
	}
	if v := get("AUTH_SESSION_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.Session.IdleTimeout = d
		}
	}
	if v := get("AUTH_SESSION_ABSOLUTE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.Session.AbsoluteTimeout = d
		}
	}
	if v := get("AUTH_BOOTSTRAP_ADMIN_USERNAME"); v != "" {
		cfg.Auth.BootstrapAdmin.Username = v
	}
	if v := get("AUTH_BOOTSTRAP_ADMIN_PASSWORD_FILE"); v != "" {
		cfg.Auth.BootstrapAdmin.PasswordFile = v
	}
	if v := get("AUTH_BOOTSTRAP_ADMIN_TENANT"); v != "" {
		cfg.Auth.BootstrapAdmin.Tenant = v
	}
	if v := get("AUTH_BOOTSTRAP_ADMIN_KEEP_ENABLED"); v != "" {
		cfg.Auth.BootstrapAdmin.KeepEnabled = strings.ToLower(v) == "true" || v == "1"
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
	if v := get("OBJECT_STORAGE_EXTERNAL_ENDPOINT"); v != "" {
		cfg.ObjectStorage.ExternalEndpoint = v
	}
	if v := get("OBJECT_STORAGE_REGION"); v != "" {
		cfg.ObjectStorage.Region = v
	}
	if v := get("OBJECT_STORAGE_ACCESS_KEY_FILE"); v != "" {
		cfg.ObjectStorage.AccessKeyFile = v
	}
	if v := get("OBJECT_STORAGE_SECRET_KEY_FILE"); v != "" {
		cfg.ObjectStorage.SecretKeyFile = v
	}
	if v := get("OBJECT_STORAGE_USE_PATH_STYLE"); v != "" {
		cfg.ObjectStorage.UsePathStyle = strings.ToLower(v) == "true" || v == "1"
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
	if v := get("TELEMETRY_OTLP_ENDPOINT"); v != "" {
		cfg.Telemetry.OTLPEndpoint = v
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
	if v := get("OPERATOR_KUBECONFIG"); v != "" {
		cfg.Operator.Kubeconfig = v
	}
	if v := get("OPERATOR_SERVICE_ACCOUNT"); v != "" {
		cfg.Operator.ServiceAccount = v
	}
	if v := get("OPERATOR_NAMESPACE"); v != "" {
		cfg.Operator.Namespace = v
	}
	if v := get("OPERATOR_SECRET_READER_CLUSTER_ROLE"); v != "" {
		cfg.Operator.SecretReaderClusterRole = v
	}
	if v := get("OPERATOR_MODE"); v != "" {
		cfg.Operator.Mode = v
	}
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseBindings reads "kind:name=role,kind:name=role".
func parseBindings(v string) []BindingSetting {
	var out []BindingSetting
	for _, item := range splitList(v) {
		left, role, ok := strings.Cut(item, "=")
		kind, name, ok2 := strings.Cut(left, ":")
		if ok && ok2 {
			out = append(out, BindingSetting{Kind: kind, Name: name, Role: role})
		}
	}
	return out
}

func (a AuthConfig) validate(publicURL string) error {
	switch a.OIDC.DefaultRole {
	case "", "viewer", "triager", "admin":
	default:
		return fmt.Errorf("config: auth.oidc.defaultRole must be viewer, triager, admin or empty, got %q", a.OIDC.DefaultRole)
	}
	for _, b := range a.OIDC.Bindings {
		if (b.Kind != "user" && b.Kind != "group") || b.Name == "" || (b.Role != "viewer" && b.Role != "triager" && b.Role != "admin") {
			return fmt.Errorf("config: invalid auth.oidc binding %+v", b)
		}
	}
	if ba := a.BootstrapAdmin; ba.PasswordFile != "" {
		switch {
		case ba.Username == "" || len(ba.Username) > 100:
			return fmt.Errorf("config: auth.bootstrapAdmin.username must be 1 to 100 characters")
		case a.Session.KeyFile == "":
			return fmt.Errorf("config: auth.session.keyFile is required when auth.bootstrapAdmin.passwordFile is set (it signs sessions)")
		}
	}
	if a.OIDC.Issuer == "" {
		return nil
	}
	switch {
	case a.OIDC.ClientID == "":
		return fmt.Errorf("config: auth.oidc.clientId is required when auth.oidc.issuer is set")
	case a.Session.KeyFile == "":
		return fmt.Errorf("config: auth.session.keyFile is required when auth.oidc.issuer is set")
	case publicURL == "":
		return fmt.Errorf("config: server.publicUrl is required when auth.oidc.issuer is set (it builds the redirect URI)")
	}
	return nil
}
