package domain_test

import (
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func TestConnector_Validate(t *testing.T) {
	tests := []struct {
		name    string
		conn    domain.Connector
		wantErr bool
	}{
		{
			name: "valid jira connector with https",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "jira-sec",
				Type:     domain.ConnectorTypeJira,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeJira,
					Jira: &domain.JiraConnectorConfig{
						URL: "https://example.com/jira",
						CredentialsSecretRef: domain.SecretKeyRef{
							Name: "jira-creds",
							Key:  "apiToken",
						},
						DefaultProject: "SEC",
						IssueType:      "Bug",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "jira connector with ssrf loopback url rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "jira-internal",
				Type:     domain.ConnectorTypeJira,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeJira,
					Jira: &domain.JiraConnectorConfig{
						URL: "https://127.0.0.1:8080",
						CredentialsSecretRef: domain.SecretKeyRef{
							Name: "jira-creds",
							Key:  "apiToken",
						},
						DefaultProject: "SEC",
						IssueType:      "Bug",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "jira connector with metadata service ip rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "jira-metadata",
				Type:     domain.ConnectorTypeJira,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeJira,
					Jira: &domain.JiraConnectorConfig{
						URL: "https://169.254.169.254/latest",
						CredentialsSecretRef: domain.SecretKeyRef{
							Name: "jira-creds",
							Key:  "apiToken",
						},
						DefaultProject: "SEC",
						IssueType:      "Bug",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "jira connector with alibaba cloud metadata ip rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "jira-alibaba-metadata",
				Type:     domain.ConnectorTypeJira,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeJira,
					Jira: &domain.JiraConnectorConfig{
						URL: "https://100.100.100.200/latest",
						CredentialsSecretRef: domain.SecretKeyRef{
							Name: "jira-creds",
							Key:  "apiToken",
						},
						DefaultProject: "SEC",
						IssueType:      "Bug",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "webhook with multicast ip rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "webhook-multicast",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL: "https://224.0.0.1/notify",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported post-phase 3 connector type rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "gitlab-sec",
				Type:     domain.ConnectorTypeGitLab,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeGitLab,
				},
			},
			wantErr: true,
		},
		{
			name: "valid webhook connector",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "audit-webhook",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL:    "https://example.com/events",
						Format: "cloudevents",
						Headers: map[string]string{
							"X-Custom-Env": "production",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "webhook with forbidden authorization header rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "bad-webhook",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL: "https://example.com/events",
						Headers: map[string]string{
							"Authorization": "Bearer secret-token",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "webhook with forbidden host header rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "bad-host-webhook",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL: "https://example.com/events",
						Headers: map[string]string{
							"Host": "evil.internal",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "webhook with header crlf injection rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "crlf-webhook",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL: "https://example.com/events",
						Headers: map[string]string{
							"X-Env": "prod\r\nInjected-Header: evil",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "webhook with plaintext apikey rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "secret-webhook",
				Type:     domain.ConnectorTypeWebhook,
				Spec: domain.ConnectorSpec{
					Type: domain.ConnectorTypeWebhook,
					Webhook: &domain.WebhookConnectorConfig{
						URL: "https://example.com/events",
						Headers: map[string]string{
							"X-API-Key": "apikey-12345",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "slack with contradictory inbound direction rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "slack-inbound",
				Type:     domain.ConnectorTypeSlack,
				Spec: domain.ConnectorSpec{
					Type:      domain.ConnectorTypeSlack,
					Direction: domain.DirectionInbound,
					Slack: &domain.SlackConnectorConfig{
						TokenSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
						DefaultChannel: "#alerts",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "dependency-track with contradictory outbound direction rejected",
			conn: domain.Connector{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "dt-outbound",
				Type:     domain.ConnectorTypeDependencyTrack,
				Spec: domain.ConnectorSpec{
					Type:      domain.ConnectorTypeDependencyTrack,
					Direction: domain.DirectionOutbound,
					DependencyTrack: &domain.DependencyTrackConnectorConfig{
						URL: "https://example.com",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conn.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestConnector_Direction(t *testing.T) {
	// 1. Inbound for DependencyTrack
	dtConn := domain.Connector{
		Type: domain.ConnectorTypeDependencyTrack,
	}
	if dtConn.Direction() != domain.DirectionInbound {
		t.Errorf("expected DirectionInbound for DT, got %s", dtConn.Direction())
	}

	// 2. Outbound for Slack
	slackConn := domain.Connector{
		Type: domain.ConnectorTypeSlack,
	}
	if slackConn.Direction() != domain.DirectionOutbound {
		t.Errorf("expected DirectionOutbound for Slack, got %s", slackConn.Direction())
	}

	// 3. Bidirectional for Jira with two-way sync
	jiraConn := domain.Connector{
		Type: domain.ConnectorTypeJira,
		Spec: domain.ConnectorSpec{
			Jira: &domain.JiraConnectorConfig{TwoWaySync: true},
		},
	}
	if jiraConn.Direction() != domain.DirectionBidirectional {
		t.Errorf("expected DirectionBidirectional for Jira with two-way sync, got %s", jiraConn.Direction())
	}

	// 4. Explicit override in spec
	customConn := domain.Connector{
		Type: domain.ConnectorTypeWebhook,
		Spec: domain.ConnectorSpec{
			Direction: domain.DirectionBidirectional,
		},
	}
	if customConn.Direction() != domain.DirectionBidirectional {
		t.Errorf("expected explicit direction to be honoured, got %s", customConn.Direction())
	}
}

func TestConnector_Conditions(t *testing.T) {
	conn := domain.Connector{
		Name: "test-conn",
		Type: domain.ConnectorTypeSlack,
	}

	if conn.IsConnected() {
		t.Error("expected IsConnected to be false initially")
	}

	conn.SetCondition("Connected", "True", "AuthOK", "Slack token verified")
	if !conn.IsConnected() {
		t.Error("expected IsConnected to be true after setting True condition")
	}

	cond := conn.GetCondition("Connected")
	if cond == nil || cond.Reason != "AuthOK" {
		t.Errorf("expected condition with reason AuthOK, got %v", cond)
	}

	conn.SetCondition("Connected", "False", "AuthFailed", "Invalid token")
	if conn.IsConnected() {
		t.Error("expected IsConnected to be false after updating to False")
	}
}
