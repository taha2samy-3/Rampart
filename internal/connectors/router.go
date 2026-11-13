package connectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// SecretResolver resolves stored secret material for a connector.
type SecretResolver interface {
	GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error)
}

// NotificationRouter routes security events and findings to active connectors with D25 digests.
type NotificationRouter struct {
	store          store.Store
	secretResolver SecretResolver
	client         *SafeClient
}

// NewNotificationRouter creates a new notification routing engine.
func NewNotificationRouter(st store.Store, resolver SecretResolver, client *SafeClient) *NotificationRouter {
	if client == nil {
		client = NewSafeClient()
	}
	return &NotificationRouter{
		store:          st,
		secretResolver: resolver,
		client:         client,
	}
}

// RouteNotification dispatches a message to all active notification connectors of a tenant.
func (r *NotificationRouter) RouteNotification(ctx context.Context, tenantID uuid.UUID, msg NotificationMessage) []error {
	connectors, err := r.store.ListConnectors(ctx, tenantID)
	if err != nil {
		return []error{fmt.Errorf("router: failed to list connectors: %w", err)}
	}

	var errs []error
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, conn := range connectors {
		if !conn.IsConnected() && conn.GetCondition("Connected") != nil && conn.GetCondition("Connected").Status == "False" {
			continue // Skip connectors known to be failing
		}

		notifier, err := r.buildNotifier(ctx, tenantID, conn)
		if err != nil {
			errs = append(errs, fmt.Errorf("connector %q build error: %w", conn.Name, err))
			continue
		}
		if notifier == nil {
			continue
		}

		wg.Add(1)
		go func(n Notifier, name string) {
			defer wg.Done()
			if sendErr := n.Send(ctx, msg); sendErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("connector %q send failed: %w", name, sendErr))
				mu.Unlock()
			}
		}(notifier, conn.Name)
	}

	wg.Wait()
	return errs
}

// RouteIngestRunFindings processes findings from an ingest run, enforcing the D25 digest threshold (>20 findings).
func (r *NotificationRouter) RouteIngestRunFindings(ctx context.Context, tenantID uuid.UUID, appName string, findings []*domain.Finding) []error {
	if len(findings) == 0 {
		return nil
	}

	// D25 Digest threshold rule: more than 20 findings in one run produce one summary message.
	if len(findings) > 20 {
		var critCount, highCount, medCount, lowCount, infoCount int
		for _, f := range findings {
			switch strings.ToLower(string(f.Severity)) {
			case "critical":
				critCount++
			case "high":
				highCount++
			case "medium":
				medCount++
			case "low":
				lowCount++
			default:
				infoCount++
			}
		}

		highestSev := "info"
		if critCount > 0 {
			highestSev = "critical"
		} else if highCount > 0 {
			highestSev = "high"
		} else if medCount > 0 {
			highestSev = "medium"
		} else if lowCount > 0 {
			highestSev = "low"
		}

		summary := fmt.Sprintf("Ingest run produced %d findings for %s:\n• Critical: %d\n• High: %d\n• Medium: %d\n• Low: %d\n• Info: %d",
			len(findings), appName, critCount, highCount, medCount, lowCount, infoCount)

		digestMsg := NotificationMessage{
			ID:          uuid.New().String(),
			TenantID:    tenantID.String(),
			AppName:     appName,
			Title:       fmt.Sprintf("%d findings detected in %s (Digest)", len(findings), appName),
			Summary:     summary,
			Severity:    highestSev,
			Timestamp:   time.Now().UTC(),
			IsDigest:    true,
			DigestCount: len(findings),
		}

		return r.RouteNotification(ctx, tenantID, digestMsg)
	}

	// Below 20 findings: send per-finding notifications
	var allErrs []error
	for _, f := range findings {
		msg := NotificationMessage{
			ID:        uuid.New().String(),
			TenantID:  tenantID.String(),
			AppName:   appName,
			Title:     f.Title,
			Summary:   f.Description,
			Severity:  strings.ToLower(string(f.Severity)),
			FindingID: f.ID.String(),
			Timestamp: time.Now().UTC(),
		}
		if errs := r.RouteNotification(ctx, tenantID, msg); len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}
	}
	return allErrs
}

func (r *NotificationRouter) buildNotifier(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) (Notifier, error) {
	switch conn.Type {
	case domain.ConnectorTypeSlack:
		if conn.Spec.Slack == nil {
			return nil, nil
		}
		token := ""
		if r.secretResolver != nil && conn.Spec.Slack.TokenSecretRef.Name != "" {
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Slack.TokenSecretRef.Key)
			if b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey); err == nil {
				token = string(b)
			}
		}
		return NewSlackNotifier(r.client, token, conn.Spec.Slack.DefaultChannel), nil

	case domain.ConnectorTypeTeams:
		if conn.Spec.Teams == nil {
			return nil, nil
		}
		webhookURL := ""
		if r.secretResolver != nil && conn.Spec.Teams.WebhookSecretRef.Name != "" {
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Teams.WebhookSecretRef.Key)
			if b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey); err == nil {
				webhookURL = string(b)
			}
		}
		return NewTeamsNotifier(r.client, webhookURL), nil

	case domain.ConnectorTypeWebhook:
		if conn.Spec.Webhook == nil {
			return nil, nil
		}
		var secret []byte
		if r.secretResolver != nil && conn.Spec.Webhook.SecretRef.Name != "" {
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Webhook.SecretRef.Key)
			secret, _ = r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
		}
		return NewWebhookNotifier(r.client, conn.Spec.Webhook.URL, secret, conn.Spec.Webhook.Format, conn.Spec.Webhook.Headers), nil

	case domain.ConnectorTypeEmail:
		if conn.Spec.Email == nil {
			return nil, nil
		}
		username, password := "", ""
		if r.secretResolver != nil && conn.Spec.Email.SMTP.CredentialsSecretRef.Name != "" {
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Key)
			if b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey); err == nil {
				parts := strings.SplitN(string(b), ":", 2)
				if len(parts) == 2 {
					username, password = parts[0], parts[1]
				}
			}
		}
		return NewEmailNotifier(conn.Spec.Email.SMTP, conn.Spec.Email.From, conn.Spec.Email.To, username, password), nil

	default:
		return nil, nil
	}
}
