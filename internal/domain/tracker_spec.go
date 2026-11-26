package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TrackerKindExternal is the kind under which ClusterExternalTracker and ExternalTracker
// resources are stored in cluster_policy and policy_object (mirrors AnalyzerKindExternal).
const TrackerKindExternal = "external_tracker"

// DefaultTrackerTimeout bounds external tracker gRPC calls when the CRD leaves timeoutSeconds unset.
const DefaultTrackerTimeout = 30 * time.Second

// MaxTrackerTimeout prevents unbounded hung RPCs against an unreachable tracker container.
const MaxTrackerTimeout = 5 * time.Minute

// ExternalTrackerSpec defines the gRPC microservice endpoint for a ClusterExternalTracker or ExternalTracker CRD.
type ExternalTrackerSpec struct {
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
		Insecure    *bool         `json:"insecure,omitempty"`
		CASecretRef *SecretKeyRef `json:"caSecretRef,omitempty"`
	} `json:"tls,omitempty"`
	Auth struct {
		SecretRef *SecretKeyRef `json:"secretRef,omitempty"`
	} `json:"auth,omitempty"`
}

// ParseExternalTrackerSpec validates an external tracker CRD spec.
// When tenantScoped is true (namespaced ExternalTracker), arbitrary endpoints are rejected
// to prevent SSRF: only an in-cluster Kubernetes Service may be targeted.
func ParseExternalTrackerSpec(raw []byte, tenantScoped bool) (ExternalTrackerSpec, error) {
	var s ExternalTrackerSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("spec is not a valid external tracker spec: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(s.Protocol)) {
	case "", "grpc":
		s.Protocol = "grpc"
	case "http":
		return s, fmt.Errorf("protocol http is not implemented for external trackers: use grpc")
	default:
		return s, fmt.Errorf("protocol %q is not valid (use grpc)", s.Protocol)
	}

	hasEndpoint := strings.TrimSpace(s.Endpoint) != ""
	hasService := s.Service.Name != "" || s.Service.Port != 0 || s.Service.Namespace != ""
	switch {
	case hasEndpoint && hasService:
		return s, fmt.Errorf("name the tracker by endpoint or by service, not both")
	case !hasEndpoint && !hasService:
		return s, fmt.Errorf("the tracker has no address: set service (name and port) or endpoint (host:port)")
	case hasEndpoint:
		if tenantScoped {
			return s, fmt.Errorf("a namespaced ExternalTracker may name a service, not an endpoint: use ClusterExternalTracker for external endpoints")
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
			return s, fmt.Errorf("service.port %d is not a valid port", s.Service.Port)
		}
	}

	if s.TimeoutSeconds < 0 || time.Duration(s.TimeoutSeconds)*time.Second > MaxTrackerTimeout {
		return s, fmt.Errorf("timeoutSeconds %d is outside 0 to %d", s.TimeoutSeconds, int(MaxTrackerTimeout/time.Second))
	}
	return s, nil
}

// IsEnabled is true unless enabled is explicitly false.
func (s ExternalTrackerSpec) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// UseTLS returns true only when tls.insecure is explicitly false.
func (s ExternalTrackerSpec) UseTLS() bool { return s.TLS.Insecure != nil && !*s.TLS.Insecure }

// Timeout returns the configured call timeout or DefaultTrackerTimeout.
func (s ExternalTrackerSpec) Timeout() time.Duration {
	if s.TimeoutSeconds > 0 {
		return time.Duration(s.TimeoutSeconds) * time.Second
	}
	return DefaultTrackerTimeout
}

// Target resolves the dial target for this tracker service or endpoint.
func (s ExternalTrackerSpec) Target(defaultNamespace string) string {
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

// ExternalTrackerRef identifies a ClusterExternalTracker or namespaced ExternalTracker resource.
type ExternalTrackerRef struct {
	Scope     string `json:"scope,omitempty"` // "cluster" | "tenant"
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// ExternalTrackerConnectorConfig configures a tenant ticketing binding backed by an external tracker container.
type ExternalTrackerConnectorConfig struct {
	TrackerRef       ExternalTrackerRef      `json:"trackerRef"`
	Provider         string                  `json:"provider,omitempty"`
	DefaultProject   string                  `json:"defaultProject,omitempty"`
	AccountID        string                  `json:"accountId,omitempty"`
	Config           json.RawMessage         `json:"config,omitempty"`
	Secrets          map[string]SecretKeyRef `json:"secrets,omitempty"`
	TwoWaySync       bool                    `json:"twoWaySync,omitempty"`
	WebhookSecretRef SecretKeyRef            `json:"webhookSecretRef,omitempty"`
	StatusMapping    JiraStatusMapping       `json:"statusMapping,omitempty"`
	CustomFields     map[string]string       `json:"customFields,omitempty"`
}

// StoredTrackerObject is a persisted ClusterExternalTracker or ExternalTracker record.
type StoredTrackerObject struct {
	Kind      string    `json:"kind"`   // TrackerKindExternal
	Origin    string    `json:"origin"` // "cluster" or "tenant"
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	Spec      []byte    `json:"spec"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TrackerStore provides access to ClusterExternalTracker and ExternalTracker definitions visible to a tenant.
type TrackerStore interface {
	ListTrackers(ctx context.Context, tenantID uuid.UUID) ([]StoredTrackerObject, error)
	GetTracker(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string) (StoredTrackerObject, bool, error)
}

// TrackerEvent records health probes, credential checks, or delivery outcomes for a tracker container.
type TrackerEvent struct {
	ID        uuid.UUID         `json:"id"`
	Scope     string            `json:"scope"` // "cluster" or "tenant"
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Event     string            `json:"event"`   // "test" | "check"
	Outcome   string            `json:"outcome"` // "succeeded" | "failed"
	Message   string            `json:"message"`
	Detail    map[string]string `json:"detail,omitempty"`
	Duration  time.Duration     `json:"-"`
	Actor     string            `json:"actor,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// TrackerEvents persists and retrieves recent tracker container test events per tenant.
type TrackerEvents interface {
	RecordTrackerEvent(ctx context.Context, tenantID uuid.UUID, ev TrackerEvent) error
	ListTrackerEvents(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string, limit int) ([]TrackerEvent, error)
}

// TicketSummary represents an opened ticket linked to findings for the Ticketing queue view.
type TicketSummary struct {
	ID           uuid.UUID `json:"id"`
	Connector    string    `json:"connector"`
	ExternalRef  string    `json:"external_ref"`
	URL          string    `json:"url,omitempty"`
	State        string    `json:"state"`
	FindingCount int       `json:"finding_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TicketOutboxItem represents a reserved or failed ticket creation entry in action_ledger.
type TicketOutboxItem struct {
	FindingID     uuid.UUID `json:"finding_id"`
	FindingTitle  string    `json:"finding_title,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastError     string    `json:"last_error,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TicketQueueReader reads opened tickets and pending/failed outbox entries for a tenant.
type TicketQueueReader interface {
	ListTickets(ctx context.Context, tenantID uuid.UUID, limit int) ([]TicketSummary, error)
	ListTicketOutbox(ctx context.Context, tenantID uuid.UUID, limit int) ([]TicketOutboxItem, error)
}
