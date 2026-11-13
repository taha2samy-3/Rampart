package domain

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Tracker creates and manages external issues/tickets for findings (Milestone 3.2, D23, D66, D70).
type Tracker interface {
	CreateIssue(ctx context.Context, finding *Finding, appName string) (ticketID string, ticketURL string, err error)
	FindIssueByLabel(ctx context.Context, label string) (ticketID string, ticketURL string, err error)
	Comment(ctx context.Context, ticketRef, comment string) error
	Close(ctx context.Context, ticketRef string) error
	Check(ctx context.Context) error
}

// TrackerResolver resolves external issue trackers for a tenant (Milestone 3.2, D66).
type TrackerResolver interface {
	ResolveTracker(ctx context.Context, tenantID uuid.UUID) (Tracker, error)
}

// TrackerError represents an error returned by an external issue tracker HTTP API (D70 B4).
type TrackerError struct {
	Status  int
	Message string
}

func (e *TrackerError) Error() string {
	return fmt.Sprintf("tracker HTTP %d: %s", e.Status, e.Message)
}

// IsFatalTrackerError returns true and the status code for non-recoverable 4xx errors (D70 B4).
func IsFatalTrackerError(err error) (bool, int) {
	var te *TrackerError
	if errors.As(err, &te) {
		switch te.Status {
		case 400, 401, 403, 404, 422:
			return true, te.Status
		}
		return false, te.Status
	}
	return false, 0
}

// Ticket represents an external issue/ticket opened for findings (D70 B1).
type Ticket struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Connector   string    `json:"connector"`
	ExternalRef string    `json:"external_ref"`
	URL         string    `json:"url"`
	State       string    `json:"state"` // e.g. "open", "closed"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ConnectorTicketingPolicy configures automated ticket opening (D70 B3).
type ConnectorTicketingPolicy struct {
	OnCritical bool              `json:"onCritical,omitempty"`
	MinBand    string            `json:"minBand,omitempty"`
	Project    string            `json:"project,omitempty"`
	Projects   map[string]string `json:"projects,omitempty"`
	MaxPerHour int               `json:"maxPerHour,omitempty"`
}

var (
	ErrConnectorInvalid      = errors.New("connector: invalid specification")
	ErrConnectorNotSupported = errors.New("connector: type not supported in Phase 3")

	headerNameRegex  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	forbiddenHeaders = map[string]bool{
		"host":                    true,
		"authorization":           true,
		"proxy-authorization":     true,
		"cookie":                  true,
		"set-cookie":              true,
		"x-rampart-signature-256": true,
		"content-length":          true,
		"content-type":            true,
		"connection":              true,
		"upgrade":                 true,
		"transfer-encoding":       true,
	}
)

// ConnectorType defines the kind of external system connected.
type ConnectorType string

const (
	// Supported Phase 3 connector types
	ConnectorTypeJira            ConnectorType = "jira"
	ConnectorTypeGitHub          ConnectorType = "github"
	ConnectorTypeSlack           ConnectorType = "slack"
	ConnectorTypeTeams           ConnectorType = "teams"
	ConnectorTypeEmail           ConnectorType = "email"
	ConnectorTypeWebhook         ConnectorType = "webhook"
	ConnectorTypeDependencyTrack ConnectorType = "dependencyTrack"

	// Deferred post-Phase 3 connector types
	ConnectorTypeGitLab      ConnectorType = "gitlab"
	ConnectorTypeAzureBoards ConnectorType = "azureBoards"
	ConnectorTypeServiceNow  ConnectorType = "serviceNow"
	ConnectorTypeSonarQube   ConnectorType = "sonarqube"
)

// ConnectorDirection indicates the flow of data relative to Rampart (docs/19, docs/20).
type ConnectorDirection string

const (
	DirectionOutbound      ConnectorDirection = "outbound"
	DirectionInbound       ConnectorDirection = "inbound"
	DirectionBidirectional ConnectorDirection = "bidirectional"
)

// JiraStatusMapping maps Jira resolution to Rampart vulnerability triage state (docs/16 D27).
type JiraStatusMapping struct {
	ClosedStatuses    []string          `json:"closedStatuses,omitempty"`
	ResolutionToState map[string]string `json:"resolutionToState,omitempty"`
}

// JiraConnectorConfig holds Jira Cloud integration settings.
type JiraConnectorConfig struct {
	URL                  string       `json:"url"`
	CredentialsSecretRef SecretKeyRef `json:"credentialsSecretRef"` // Keys: email, apiToken (or pat)
	DefaultProject       string       `json:"defaultProject"`
	// AccountID is the Jira account Rampart calls the API as. A change made by it is Rampart's own and is never read
	// as a decision (D69).
	AccountID          string            `json:"accountId,omitempty"`
	IssueType          string            `json:"issueType"`
	SeverityToPriority map[string]string `json:"severityToPriority,omitempty"`
	StatusMapping      JiraStatusMapping `json:"statusMapping,omitempty"`
	TwoWaySync         bool              `json:"twoWaySync,omitempty"`
	// WebhookSecretRef is the secret Jira signs its webhooks with. It is NOT the API credential: a token that
	// can call Jira must not also be the thing written into Jira's webhook settings (D69).
	WebhookSecretRef SecretKeyRef      `json:"webhookSecretRef,omitempty"`
	SyncInterval     string            `json:"syncInterval,omitempty"`
	CustomFields     map[string]string `json:"customFields,omitempty"`
}

// GitHubConnectorConfig holds GitHub Issues integration settings.
type GitHubConnectorConfig struct {
	Owner                string            `json:"owner"`
	Repo                 string            `json:"repo"`
	CredentialsSecretRef SecretKeyRef      `json:"credentialsSecretRef"` // Key: token
	SeverityToLabels     map[string]string `json:"severityToLabels,omitempty"`
	DefaultLabels        []string          `json:"defaultLabels,omitempty"`
	TwoWaySync           bool              `json:"twoWaySync,omitempty"`
	// WebhookSecretRef is the secret of the repository webhook (X-Hub-Signature-256), separate from the token.
	WebhookSecretRef SecretKeyRef `json:"webhookSecretRef,omitempty"`
}

// SlackConnectorConfig holds Slack bot integration settings (chat.postMessage per D69).
type SlackConnectorConfig struct {
	TokenSecretRef SecretKeyRef `json:"tokenSecretRef"` // Key: token (xoxb-...)
	DefaultChannel string       `json:"defaultChannel"` // e.g. #security-alerts or C123456
}

// TeamsConnectorConfig holds Microsoft Teams Workflows webhook settings (Power Automate per D69).
type TeamsConnectorConfig struct {
	WebhookSecretRef SecretKeyRef `json:"webhookSecretRef"` // Key: url
}

// EmailTLSMode specifies the encryption mode for SMTP connections.
type EmailTLSMode string

const (
	EmailTLSModeStartTLS EmailTLSMode = "starttls" // Mandatory STARTTLS on port 587/25 (default)
	EmailTLSModeImplicit EmailTLSMode = "implicit" // Implicit TLS (SMTPS) on port 465
	EmailTLSModeInsecure EmailTLSMode = "insecure" // Plaintext unencrypted (internal/testing only)
)

// EmailSMTPConfig contains SMTP server connection settings.
type EmailSMTPConfig struct {
	Host                 string       `json:"host"`
	Port                 int          `json:"port"`
	CredentialsSecretRef SecretKeyRef `json:"credentialsSecretRef,omitempty"` // Keys: username, password
	TLS                  bool         `json:"tls,omitempty"`                  // Legacy boolean (true => implicit TLS)
	TLSMode              EmailTLSMode `json:"tlsMode,omitempty"`              // "starttls" | "implicit" | "insecure"
}

// NotificationRoutingRule specifies filter criteria for dispatching notifications to a connector.
type NotificationRoutingRule struct {
	MinSeverity  Severity `json:"minSeverity,omitempty"`  // e.g. "high" (filters out lower severities)
	Applications []string `json:"applications,omitempty"` // Filter by application names (empty means all)
	Events       []string `json:"events,omitempty"`       // Filter by event types (empty means all)
}

// EmailConnectorConfig holds outbound email notification settings.
type EmailConnectorConfig struct {
	SMTP EmailSMTPConfig `json:"smtp"`
	From string          `json:"from"`
	To   []string        `json:"to"`
}

// WebhookConnectorConfig holds HMAC-SHA256 signed webhook settings (CloudEvents per D69).
type WebhookConnectorConfig struct {
	URL       string            `json:"url"`
	SecretRef SecretKeyRef      `json:"secretRef,omitempty"` // For HMAC-SHA256 signature
	Format    string            `json:"format,omitempty"`    // "cloudevents" | "raw"
	Headers   map[string]string `json:"headers,omitempty"`
}

// DependencyTrackConnectorConfig holds Dependency-Track API settings (docs/10).
type DependencyTrackConnectorConfig struct {
	URL                  string       `json:"url"`
	CredentialsSecretRef SecretKeyRef `json:"credentialsSecretRef"` // Key: apiKey
}

// ConnectorSpec represents the configuration of a Connector resource.
type ConnectorSpec struct {
	Type            ConnectorType                   `json:"type"`
	Direction       ConnectorDirection              `json:"direction,omitempty"` // "outbound" | "inbound" | "bidirectional"
	Ticketing       *ConnectorTicketingPolicy       `json:"ticketing,omitempty"` // Automated ticketing policy (D70 B3)
	Routing         *NotificationRoutingRule        `json:"routing,omitempty"`   // Routing filters (D25/D69 noise reduction)
	Jira            *JiraConnectorConfig            `json:"jira,omitempty"`
	GitHub          *GitHubConnectorConfig          `json:"github,omitempty"`
	Slack           *SlackConnectorConfig           `json:"slack,omitempty"`
	Teams           *TeamsConnectorConfig           `json:"teams,omitempty"`
	Email           *EmailConnectorConfig           `json:"email,omitempty"`
	Webhook         *WebhookConnectorConfig         `json:"webhook,omitempty"`
	DependencyTrack *DependencyTrackConnectorConfig `json:"dependencyTrack,omitempty"`
}

// ConnectorCondition describes the state of a connector at a point in time.
type ConnectorCondition struct {
	Type               string    `json:"type"`   // e.g. "Connected"
	Status             string    `json:"status"` // "True" | "False" | "Unknown"
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// ConnectorStatus holds the observed runtime status of a Connector.
type ConnectorStatus struct {
	ObservedGeneration int64                `json:"observedGeneration,omitempty"`
	Conditions         []ConnectorCondition `json:"conditions,omitempty"`
	WebhookURL         string               `json:"webhookURL,omitempty"`
	AccountID          string               `json:"accountId,omitempty"`
	LastSync           *time.Time           `json:"lastSync,omitempty"`
}

// Connector is the domain model for external tool connectors.
type Connector struct {
	ID        uuid.UUID       `json:"id"`
	TenantID  uuid.UUID       `json:"tenantId"`
	Namespace string          `json:"namespace,omitempty"`
	Name      string          `json:"name"`
	Type      ConnectorType   `json:"type"`
	Spec      ConnectorSpec   `json:"spec"`
	Status    ConnectorStatus `json:"status"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// Direction returns the effective communication direction for this connector.
func (c *Connector) Direction() ConnectorDirection {
	if c.Spec.Direction != "" {
		return c.Spec.Direction
	}
	switch c.Type {
	case ConnectorTypeDependencyTrack, ConnectorTypeSonarQube:
		return DirectionInbound
	case ConnectorTypeJira:
		if c.Spec.Jira != nil && c.Spec.Jira.TwoWaySync {
			return DirectionBidirectional
		}
		return DirectionOutbound
	case ConnectorTypeGitHub:
		if c.Spec.GitHub != nil && c.Spec.GitHub.TwoWaySync {
			return DirectionBidirectional
		}
		return DirectionOutbound
	default:
		return DirectionOutbound
	}
}

// Validate checks the structural validity, SSRF safety, and header constraints of a Connector.
func (c *Connector) Validate() error {
	return c.ValidateWithAllowlist(nil)
}

// ValidateWithAllowlist validates a Connector with a platform administrator SSRF allowlist (D69).
func (c *Connector) ValidateWithAllowlist(allowlist *PlatformSSRFAllowlist) error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: connector name is required", ErrConnectorInvalid)
	}
	if c.Type == "" {
		return fmt.Errorf("%w: connector type is required", ErrConnectorInvalid)
	}

	// Default direction if empty, or validate that explicit direction does not contradict connector type (D69)
	if c.Spec.Direction == "" {
		c.Spec.Direction = c.Direction()
	} else {
		switch c.Type {
		case ConnectorTypeSlack, ConnectorTypeTeams, ConnectorTypeEmail, ConnectorTypeWebhook:
			if c.Spec.Direction != DirectionOutbound {
				return fmt.Errorf("%w: connector type %q only supports outbound direction, got %q", ErrConnectorInvalid, c.Type, c.Spec.Direction)
			}
		case ConnectorTypeDependencyTrack, ConnectorTypeSonarQube:
			if c.Spec.Direction != DirectionInbound {
				return fmt.Errorf("%w: connector type %q only supports inbound direction, got %q", ErrConnectorInvalid, c.Type, c.Spec.Direction)
			}
		case ConnectorTypeJira, ConnectorTypeGitHub:
			if c.Spec.Direction != DirectionOutbound && c.Spec.Direction != DirectionBidirectional {
				return fmt.Errorf("%w: tracker connector %q must be outbound or bidirectional, got %q", ErrConnectorInvalid, c.Type, c.Spec.Direction)
			}
		}
	}

	// Reject unimplemented types per user requirement
	switch c.Type {
	case ConnectorTypeGitLab, ConnectorTypeAzureBoards, ConnectorTypeServiceNow, ConnectorTypeSonarQube:
		return fmt.Errorf("%w: connector type %q is not supported in Phase 3 (planned for future phases)", ErrConnectorNotSupported, c.Type)
	}

	if c.Spec.Routing != nil && c.Spec.Routing.MinSeverity != "" {
		s := strings.ToLower(string(c.Spec.Routing.MinSeverity))
		switch s {
		case "critical", "high", "medium", "low", "info":
			// valid
		default:
			return fmt.Errorf("%w: invalid routing minSeverity %q (must be critical, high, medium, low, or info)", ErrConnectorInvalid, c.Spec.Routing.MinSeverity)
		}
	}

	switch c.Type {
	case ConnectorTypeJira:
		if c.Spec.Jira == nil {
			return fmt.Errorf("%w: jira config is required for jira connector", ErrConnectorInvalid)
		}
		if err := ValidateConnectorURLWithAllowlist(c.Spec.Jira.URL, allowlist); err != nil {
			return fmt.Errorf("%w: invalid jira url: %w", ErrConnectorInvalid, err)
		}
		if strings.TrimSpace(c.Spec.Jira.CredentialsSecretRef.Name) == "" {
			return fmt.Errorf("%w: jira credentialsSecretRef is required", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.Jira.DefaultProject) == "" {
			return fmt.Errorf("%w: jira defaultProject is required (Rampart does not guess a project)", ErrConnectorInvalid)
		}
		if (c.Spec.Jira.TwoWaySync || c.Direction() == DirectionBidirectional) && strings.TrimSpace(c.Spec.Jira.WebhookSecretRef.Name) == "" {
			return fmt.Errorf("%w: jira webhookSecretRef is required when twoWaySync is on: an unsigned webhook is never accepted", ErrConnectorInvalid)
		}
	case ConnectorTypeGitHub:
		if c.Spec.GitHub == nil {
			return fmt.Errorf("%w: github config is required for github connector", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.GitHub.Owner) == "" || strings.TrimSpace(c.Spec.GitHub.Repo) == "" {
			return fmt.Errorf("%w: github owner and repo are required", ErrConnectorInvalid)
		}
		if (c.Spec.GitHub.TwoWaySync || c.Direction() == DirectionBidirectional) && strings.TrimSpace(c.Spec.GitHub.WebhookSecretRef.Name) == "" {
			return fmt.Errorf("%w: github webhookSecretRef is required when twoWaySync is on: an unsigned webhook is never accepted", ErrConnectorInvalid)
		}
	case ConnectorTypeSlack:
		if c.Spec.Slack == nil {
			return fmt.Errorf("%w: slack config is required for slack connector", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.Slack.DefaultChannel) == "" {
			return fmt.Errorf("%w: slack defaultChannel is required", ErrConnectorInvalid)
		}
	case ConnectorTypeTeams:
		if c.Spec.Teams == nil {
			return fmt.Errorf("%w: teams config is required for teams connector", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.Teams.WebhookSecretRef.Name) == "" {
			return fmt.Errorf("%w: teams webhookSecretRef is required", ErrConnectorInvalid)
		}
	case ConnectorTypeEmail:
		if c.Spec.Email == nil {
			return fmt.Errorf("%w: email config is required for email connector", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.Email.From) == "" || len(c.Spec.Email.To) == 0 {
			return fmt.Errorf("%w: email from and at least one to recipient are required", ErrConnectorInvalid)
		}
	case ConnectorTypeWebhook:
		if c.Spec.Webhook == nil {
			return fmt.Errorf("%w: webhook config is required for webhook connector", ErrConnectorInvalid)
		}
		if err := ValidateConnectorURLWithAllowlist(c.Spec.Webhook.URL, allowlist); err != nil {
			return fmt.Errorf("%w: invalid webhook url: %w", ErrConnectorInvalid, err)
		}
		// Validate headers: check forbidden names and valid token syntax
		for k, v := range c.Spec.Webhook.Headers {
			if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("%w: header key or value contains CRLF (header injection attempt)", ErrConnectorInvalid)
			}
			kLower := strings.ToLower(strings.TrimSpace(k))
			if forbiddenHeaders[kLower] || strings.HasPrefix(kLower, "x-hub-signature") || strings.HasPrefix(kLower, "x-rampart-signature") {
				return fmt.Errorf("%w: header %q is forbidden in webhook headers (D69); use secretRef for authentication", ErrConnectorInvalid, k)
			}
			if !headerNameRegex.MatchString(k) {
				return fmt.Errorf("%w: invalid header name %q", ErrConnectorInvalid, k)
			}
			vLower := strings.ToLower(v)
			if strings.Contains(vLower, "bearer ") || strings.Contains(vLower, "basic ") || strings.Contains(vLower, "token ") || strings.Contains(vLower, "apikey") || strings.Contains(vLower, "secret") {
				return fmt.Errorf("%w: plaintext credentials or tokens in headers are prohibited; use secretRef", ErrConnectorInvalid)
			}
		}
	case ConnectorTypeDependencyTrack:
		if c.Spec.DependencyTrack == nil {
			return fmt.Errorf("%w: dependencyTrack config is required for dependencyTrack connector", ErrConnectorInvalid)
		}
		if err := ValidateConnectorURLWithAllowlist(c.Spec.DependencyTrack.URL, allowlist); err != nil {
			return fmt.Errorf("%w: invalid dependencyTrack url: %w", ErrConnectorInvalid, err)
		}
	default:
		return fmt.Errorf("%w: unrecognized connector type %q", ErrConnectorInvalid, c.Type)
	}

	if c.Spec.Ticketing != nil {
		if c.Type != ConnectorTypeJira && c.Type != ConnectorTypeGitHub {
			return fmt.Errorf("%w: ticketing policy only supported on tracker connectors (jira, github)", ErrConnectorInvalid)
		}
		if c.Spec.Ticketing.MaxPerHour < 0 {
			return fmt.Errorf("%w: ticketing maxPerHour cannot be negative", ErrConnectorInvalid)
		}
	}

	return nil
}

// GetCondition returns the condition with the specified type, or nil if not found.
func (c *Connector) GetCondition(condType string) *ConnectorCondition {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == condType {
			return &c.Status.Conditions[i]
		}
	}
	return nil
}

// SetCondition updates or appends a condition.
func (c *Connector) SetCondition(condType, status, reason, message string) {
	now := time.Now().UTC()
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == condType {
			if c.Status.Conditions[i].Status != status {
				c.Status.Conditions[i].LastTransitionTime = now
			}
			c.Status.Conditions[i].Status = status
			c.Status.Conditions[i].Reason = reason
			c.Status.Conditions[i].Message = message
			return
		}
	}
	c.Status.Conditions = append(c.Status.Conditions, ConnectorCondition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

// IsConnected returns true if the Connected condition is "True".
func (c *Connector) IsConnected() bool {
	cond := c.GetCondition("Connected")
	return cond != nil && cond.Status == "True"
}

// IsReady returns true if the Ready condition is "True".
func (c *Connector) IsReady() bool {
	cond := c.GetCondition("Ready")
	return cond != nil && cond.Status == "True"
}

// ConnectorSecretStorageKey returns the canonical storage key for a connector secret in secret_material (D69).
// If key is empty, it defaults to "token".
func ConnectorSecretStorageKey(connectorName, key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		k = "token"
	}
	return fmt.Sprintf("connector:%s:%s", connectorName, k)
}

// ConnectorWebhookSecretStorageKey is where the secret an inbound webhook is verified with is kept in
// secret_material. It is distinct from the connector's API credential (docs/16 D69, D70).
func ConnectorWebhookSecretStorageKey(connectorName, key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		k = "secret"
	}
	return fmt.Sprintf("connector:%s:webhook:%s", connectorName, k)
}

// WebhookSecret returns the reference to the secret that verifies this connector's inbound webhooks, or nil.
func (c *Connector) WebhookSecret() *SecretKeyRef {
	switch c.Type {
	case ConnectorTypeJira:
		if c.Spec.Jira != nil && c.Spec.Jira.WebhookSecretRef.Name != "" {
			return &c.Spec.Jira.WebhookSecretRef
		}
	case ConnectorTypeGitHub:
		if c.Spec.GitHub != nil && c.Spec.GitHub.WebhookSecretRef.Name != "" {
			return &c.Spec.GitHub.WebhookSecretRef
		}
	case ConnectorTypeWebhook:
		if c.Spec.Webhook != nil && c.Spec.Webhook.SecretRef.Name != "" {
			return &c.Spec.Webhook.SecretRef
		}
	}
	return nil
}

// WebhookSecretStorageKey is the secret_material key of the secret that verifies this connector's inbound
// webhooks, or "" when none is configured. A generic webhook connector verifies with the same secret it signs
// with; Jira and GitHub have a separate one.
func (c *Connector) WebhookSecretStorageKey() string {
	ref := c.WebhookSecret()
	if ref == nil {
		return ""
	}
	if c.Type == ConnectorTypeWebhook {
		return ConnectorSecretStorageKey(c.Name, ref.Key)
	}
	return ConnectorWebhookSecretStorageKey(c.Name, ref.Key)
}
