package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrConnectorInvalid      = errors.New("connector: invalid specification")
	ErrConnectorNotSupported = errors.New("connector: type not supported in Phase 3")

	headerNameRegex  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	forbiddenHeaders = map[string]bool{
		"host":                    true,
		"authorization":           true,
		"x-rampart-signature-256": true,
		"content-length":          true,
		"content-type":            true,
		"connection":              true,
		"upgrade":                 true,
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
	URL                  string            `json:"url"`
	CredentialsSecretRef SecretKeyRef      `json:"credentialsSecretRef"` // Keys: email, apiToken (or pat)
	DefaultProject       string            `json:"defaultProject"`
	IssueType            string            `json:"issueType"`
	SeverityToPriority   map[string]string `json:"severityToPriority,omitempty"`
	StatusMapping        JiraStatusMapping `json:"statusMapping,omitempty"`
	TwoWaySync           bool              `json:"twoWaySync,omitempty"`
	SyncInterval         string            `json:"syncInterval,omitempty"`
	CustomFields         map[string]string `json:"customFields,omitempty"`
}

// GitHubConnectorConfig holds GitHub Issues integration settings.
type GitHubConnectorConfig struct {
	Owner                string            `json:"owner"`
	Repo                 string            `json:"repo"`
	CredentialsSecretRef SecretKeyRef      `json:"credentialsSecretRef"` // Key: token
	SeverityToLabels     map[string]string `json:"severityToLabels,omitempty"`
	DefaultLabels        []string          `json:"defaultLabels,omitempty"`
	TwoWaySync           bool              `json:"twoWaySync,omitempty"`
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

// EmailSMTPConfig contains SMTP server connection settings.
type EmailSMTPConfig struct {
	Host                 string       `json:"host"`
	Port                 int          `json:"port"`
	CredentialsSecretRef SecretKeyRef `json:"credentialsSecretRef,omitempty"` // Keys: username, password
	TLS                  bool         `json:"tls,omitempty"`
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
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: connector name is required", ErrConnectorInvalid)
	}
	if c.Type == "" {
		return fmt.Errorf("%w: connector type is required", ErrConnectorInvalid)
	}

	// Reject unimplemented types per user requirement
	switch c.Type {
	case ConnectorTypeGitLab, ConnectorTypeAzureBoards, ConnectorTypeServiceNow, ConnectorTypeSonarQube:
		return fmt.Errorf("%w: connector type %q is not supported in Phase 3 (planned for future phases)", ErrConnectorNotSupported, c.Type)
	}

	switch c.Type {
	case ConnectorTypeJira:
		if c.Spec.Jira == nil {
			return fmt.Errorf("%w: jira config is required for jira connector", ErrConnectorInvalid)
		}
		if err := ValidateConnectorURL(c.Spec.Jira.URL); err != nil {
			return fmt.Errorf("%w: invalid jira url: %v", ErrConnectorInvalid, err)
		}
		if strings.TrimSpace(c.Spec.Jira.CredentialsSecretRef.Name) == "" {
			return fmt.Errorf("%w: jira credentialsSecretRef is required", ErrConnectorInvalid)
		}
	case ConnectorTypeGitHub:
		if c.Spec.GitHub == nil {
			return fmt.Errorf("%w: github config is required for github connector", ErrConnectorInvalid)
		}
		if strings.TrimSpace(c.Spec.GitHub.Owner) == "" || strings.TrimSpace(c.Spec.GitHub.Repo) == "" {
			return fmt.Errorf("%w: github owner and repo are required", ErrConnectorInvalid)
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
		if err := ValidateConnectorURL(c.Spec.Webhook.URL); err != nil {
			return fmt.Errorf("%w: invalid webhook url: %v", ErrConnectorInvalid, err)
		}
		// Validate headers: check forbidden names and valid token syntax
		for k, v := range c.Spec.Webhook.Headers {
			kLower := strings.ToLower(strings.TrimSpace(k))
			if forbiddenHeaders[kLower] {
				return fmt.Errorf("%w: header %q is forbidden in webhook headers (D69); use secretRef for authentication", ErrConnectorInvalid, k)
			}
			if !headerNameRegex.MatchString(k) {
				return fmt.Errorf("%w: invalid header name %q", ErrConnectorInvalid, k)
			}
			if strings.Contains(strings.ToLower(v), "bearer ") {
				return fmt.Errorf("%w: plaintext bearer tokens in headers are prohibited; use secretRef", ErrConnectorInvalid)
			}
		}
	case ConnectorTypeDependencyTrack:
		if c.Spec.DependencyTrack == nil {
			return fmt.Errorf("%w: dependencyTrack config is required for dependencyTrack connector", ErrConnectorInvalid)
		}
		if err := ValidateConnectorURL(c.Spec.DependencyTrack.URL); err != nil {
			return fmt.Errorf("%w: invalid dependencyTrack url: %v", ErrConnectorInvalid, err)
		}
	default:
		return fmt.Errorf("%w: unrecognized connector type %q", ErrConnectorInvalid, c.Type)
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
