package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"rampart/internal/cron"
)

// The kinds an analyzer is kept under, with the cluster's and the tenants' other policies (cluster_policy and policy_object). There are two
// because the two kinds of analyzer are different things: one is a service Rampart calls over gRPC, the other is the matcher inside the server.
const (
	AnalyzerKindExternal = "external_analyzer" // ClusterExternalAnalyzer and ExternalAnalyzer
	AnalyzerKindSBOM     = "sbom_analyzer"     // ClusterSBOMAnalyzer and SBOMAnalyzer: the matcher inside the server
)

// ExternalAnalyzerSpec is the spec of a ClusterExternalAnalyzer or an ExternalAnalyzer: a service that Rampart calls with the components of an
// SBOM and that answers with vulnerabilities (pkg/api/analyzer/v1).
type ExternalAnalyzerSpec struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Service  struct {
		Name      string `json:"name,omitempty"`
		Namespace string `json:"namespace,omitempty"`
		Port      int    `json:"port,omitempty"`
	} `json:"service,omitempty"`
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	TLS            struct {
		Insecure    *bool           `json:"insecure,omitempty"`
		CASecretRef json.RawMessage `json:"caSecretRef,omitempty"`
	} `json:"tls,omitempty"`
	Auth struct {
		SecretRef json.RawMessage `json:"secretRef,omitempty"`
	} `json:"auth,omitempty"`
}

// DefaultAnalyzerTimeout is how long one call to an external analyzer may take when its spec does not say.
const DefaultAnalyzerTimeout = 60 * time.Second

// MaxAnalyzerTimeout bounds timeoutSeconds: a call that long is a hung analyzer, not a slow one.
const MaxAnalyzerTimeout = 10 * time.Minute

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ParseExternalAnalyzerSpec reads and checks the spec of an external analyzer. tenantScoped is true for the namespaced ExternalAnalyzer,
// which a tenant's namespace owns and which therefore may name only an in-cluster Service: an `endpoint` is any address, and the server would
// dial whatever a tenant wrote (docs/34 F29). What the server cannot honour is refused with its reason, not stored and ignored: a `tls` or
// `auth` block that asks for a Secret the server cannot read would otherwise give the owner a connection that is not the one they asked for.
func ParseExternalAnalyzerSpec(raw []byte, tenantScoped bool) (ExternalAnalyzerSpec, error) {
	var s ExternalAnalyzerSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("spec is not a valid external analyzer spec: %w", err)
	}
	switch strings.ToLower(s.Protocol) {
	case "", "grpc":
		s.Protocol = "grpc"
	case "http":
		return s, fmt.Errorf("protocol http is accepted by the CRD but no HTTP client is built: use grpc")
	default:
		return s, fmt.Errorf("protocol %q is neither grpc nor http", s.Protocol)
	}
	hasEndpoint, hasService := strings.TrimSpace(s.Endpoint) != "", s.Service.Name != "" || s.Service.Port != 0 || s.Service.Namespace != ""
	switch {
	case hasEndpoint && hasService:
		return s, fmt.Errorf("name the analyzer by endpoint or by service, not both")
	case !hasEndpoint && !hasService:
		return s, fmt.Errorf("the analyzer has no address: set service (name and port) or endpoint (host:port)")
	case hasEndpoint:
		if tenantScoped {
			return s, fmt.Errorf("a namespaced ExternalAnalyzer may name a service, not an endpoint: an endpoint is any address, and the server would call it for a tenant (use a ClusterExternalAnalyzer for an address outside the cluster)")
		}
		host, port, err := net.SplitHostPort(strings.TrimSpace(s.Endpoint))
		if err != nil || host == "" {
			return s, fmt.Errorf("endpoint %q is not host:port", s.Endpoint)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return s, fmt.Errorf("endpoint %q has no valid port", s.Endpoint)
		}
	default:
		if !dnsLabel.MatchString(s.Service.Name) {
			return s, fmt.Errorf("service.name %q is not a Kubernetes name (lower-case letters, digits and -)", s.Service.Name)
		}
		if s.Service.Namespace != "" && !dnsLabel.MatchString(s.Service.Namespace) {
			return s, fmt.Errorf("service.namespace %q is not a Kubernetes name", s.Service.Namespace)
		}
		if s.Service.Port < 1 || s.Service.Port > 65535 {
			return s, fmt.Errorf("service.port %d is not a port", s.Service.Port)
		}
	}
	if s.TimeoutSeconds < 0 || time.Duration(s.TimeoutSeconds)*time.Second > MaxAnalyzerTimeout {
		return s, fmt.Errorf("timeoutSeconds %d is outside 0 to %d", s.TimeoutSeconds, int(MaxAnalyzerTimeout/time.Second))
	}
	if len(s.TLS.CASecretRef) > 0 && string(s.TLS.CASecretRef) != "null" {
		return s, fmt.Errorf("tls.caSecretRef is not supported yet: the server cannot read a Secret, so a private CA cannot be trusted")
	}
	if len(s.Auth.SecretRef) > 0 && string(s.Auth.SecretRef) != "null" {
		return s, fmt.Errorf("auth.secretRef is not supported yet: the server cannot read a Secret, so the analyzer would be called without the credential")
	}
	return s, nil
}

// ParseTenantExternalAnalyzerSpec checks the spec of a namespaced ExternalAnalyzer that lives in namespace: on top of
// ParseExternalAnalyzerSpec(raw, true), the Service it names must be in its own namespace (service.namespace empty or equal).
func ParseTenantExternalAnalyzerSpec(raw []byte, namespace string) (ExternalAnalyzerSpec, error) {
	s, err := ParseExternalAnalyzerSpec(raw, true)
	if err != nil {
		return s, err
	}
	return s, serviceInOwnNamespace("ExternalAnalyzer", s.Service.Namespace, namespace)
}

// IsEnabled is true unless the spec says enabled: false.
func (s ExternalAnalyzerSpec) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// UseTLS says whether the connection is secured: only when the spec says tls.insecure is false. Otherwise the call is plaintext, as it has always been.
func (s ExternalAnalyzerSpec) UseTLS() bool { return s.TLS.Insecure != nil && !*s.TLS.Insecure }

// Timeout is how long one call may take.
func (s ExternalAnalyzerSpec) Timeout() time.Duration {
	if s.TimeoutSeconds > 0 {
		return time.Duration(s.TimeoutSeconds) * time.Second
	}
	return DefaultAnalyzerTimeout
}

// Target is the address to dial. A Service in no namespace is in defaultNamespace: the resource's own for a namespaced analyzer, "default" for a cluster one.
func (s ExternalAnalyzerSpec) Target(defaultNamespace string) string {
	if e := strings.TrimSpace(s.Endpoint); e != "" {
		return e
	}
	ns := s.Service.Namespace
	if ns == "" {
		ns = defaultNamespace
	}
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", s.Service.Name, ns, s.Service.Port)
}

// SBOMAnalyzerSpec is the spec of a ClusterSBOMAnalyzer or an SBOMAnalyzer: the matcher inside the server (internal/analyzer/matcher).
type SBOMAnalyzerSpec struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Engine  string `json:"engine,omitempty"`
	Rules   struct {
		MinConfidence     *float64 `json:"minConfidence,omitempty"`
		IncludePreRelease bool     `json:"includePreRelease,omitempty"`
		MatchDirectOnly   bool     `json:"matchDirectOnly,omitempty"`
	} `json:"rules,omitempty"`
	Sources struct {
		OSV  *bool `json:"osv,omitempty"`
		GHSA *bool `json:"ghsa,omitempty"`
		NVD  *bool `json:"nvd,omitempty"`
	} `json:"sources,omitempty"`
	Schedule string `json:"schedule,omitempty"`
}

// AnalyzerEngines are the engines the CRD allows for the matcher.
var AnalyzerEngines = []string{"hybrid", "osv", "in-process", "advisory-db"}

// ParseSBOMAnalyzerSpec reads and checks the spec of the matcher.
func ParseSBOMAnalyzerSpec(raw []byte) (SBOMAnalyzerSpec, error) {
	var s SBOMAnalyzerSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("spec is not a valid SBOM analyzer spec: %w", err)
	}
	if s.Engine == "" {
		s.Engine = "hybrid"
	}
	known := false
	for _, e := range AnalyzerEngines {
		known = known || e == s.Engine
	}
	if !known {
		return s, fmt.Errorf("engine %q is none of %s", s.Engine, strings.Join(AnalyzerEngines, ", "))
	}
	if c := s.Rules.MinConfidence; c != nil && (*c < 0 || *c > 1) {
		return s, fmt.Errorf("rules.minConfidence %v is outside 0 to 1", *c)
	}
	if s.Schedule != "" {
		if _, err := cron.Parse(s.Schedule); err != nil {
			return s, fmt.Errorf("schedule: %w", err)
		}
	}
	return s, nil
}

// IsEnabled is true unless the spec says enabled: false.
func (s SBOMAnalyzerSpec) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// StoredAnalyzerObject is an analyzer as the store keeps it: which kind, whose, and the last spec with the reason it was refused if it was.
type StoredAnalyzerObject struct {
	Kind      string    `json:"kind"`   // AnalyzerKindExternal or AnalyzerKindSBOM
	Origin    string    `json:"origin"` // "cluster" or "tenant"
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	Spec      []byte    `json:"spec"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AnalyzerStore lists the analyzers a tenant sees: the cluster's and its own.
type AnalyzerStore interface {
	ListAnalyzers(ctx context.Context, tenantID uuid.UUID) ([]StoredAnalyzerObject, error)
}

// AnalyzerEvent is one thing that happened to an analyzer: a test, or (when analyses run) an analysis. It is the answer to "is it working".
type AnalyzerEvent struct {
	ID        uuid.UUID         `json:"id"`
	Kind      string            `json:"kind"`      // "external" or "sbom"
	Scope     string            `json:"scope"`     // "cluster" or "tenant"
	Namespace string            `json:"namespace"` // of a tenant analyzer
	Name      string            `json:"name"`
	Event     string            `json:"event"`   // "test" or "analysis"
	Outcome   string            `json:"outcome"` // "succeeded" or "failed"
	Message   string            `json:"message"`
	Detail    map[string]string `json:"detail,omitempty"`
	Duration  time.Duration     `json:"-"`
	Actor     string            `json:"actor,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// AnalyzerEvents records and lists the events of analyzers. They are the tenant's: an event of a cluster analyzer is the event of the tenant that caused it.
type AnalyzerEvents interface {
	RecordAnalyzerEvent(ctx context.Context, tenantID uuid.UUID, ev AnalyzerEvent) error
	ListAnalyzerEvents(ctx context.Context, tenantID uuid.UUID, kind, scope, namespace, name string, limit int) ([]AnalyzerEvent, error)
}

// AdvisorySummary says how much advisory data the matcher inside the server has to match against: the affected ranges the OSV feed wrote.
type AdvisorySummary struct {
	Ranges     int                 `json:"ranges"`
	Ecosystems []EcosystemAdvisory `json:"ecosystems"`
}

// EcosystemAdvisory is the number of affected ranges of one ecosystem (npm, Maven, Go, ...).
type EcosystemAdvisory struct {
	Ecosystem string `json:"ecosystem"`
	Ranges    int    `json:"ranges"`
}

// AdvisorySummarizer is implemented by the stores that hold advisory data.
type AdvisorySummarizer interface {
	AdvisorySummary(ctx context.Context) (AdvisorySummary, error)
}
