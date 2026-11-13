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

// RouterConfig configures the notification router options.
type RouterConfig struct {
	PublicURL string // Base URL for constructing absolute deep links (e.g. "https://rampart.example.com")
}

// NotificationRouter routes security events and findings to active connectors with D25 digests.
type NotificationRouter struct {
	store          store.Store
	secretResolver SecretResolver
	client         *SafeClient
	publicURL      string
}

// NewNotificationRouter creates a new notification routing engine with default configuration.
func NewNotificationRouter(st store.Store, resolver SecretResolver, client *SafeClient) *NotificationRouter {
	return NewNotificationRouterWithConfig(st, resolver, client, RouterConfig{})
}

// NewNotificationRouterWithConfig creates a notification routing engine with custom settings (e.g. PublicURL).
func NewNotificationRouterWithConfig(st store.Store, resolver SecretResolver, client *SafeClient, cfg RouterConfig) *NotificationRouter {
	if client == nil {
		client = NewSafeClient()
	}
	pubURL := strings.TrimRight(cfg.PublicURL, "/")
	if pubURL == "" {
		pubURL = "https://rampart.local"
	}
	return &NotificationRouter{
		store:          st,
		secretResolver: resolver,
		client:         client,
		publicURL:      pubURL,
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

		// Apply noise-reduction routing filters (D25/D69)
		if !matchesRouting(conn.Spec.Routing, msg) {
			continue
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

		digestURL := fmt.Sprintf("%s/t/%s/applications/%s", r.publicURL, tenantID.String(), appName)
		digestMsg := NotificationMessage{
			ID:          uuid.New().String(),
			TenantID:    tenantID.String(),
			AppName:     appName,
			Title:       fmt.Sprintf("%d findings detected in %s (Digest)", len(findings), appName),
			Summary:     summary,
			Severity:    highestSev,
			URL:         digestURL,
			Timestamp:   time.Now().UTC(),
			IsDigest:    true,
			DigestCount: len(findings),
		}

		return r.RouteNotification(ctx, tenantID, digestMsg)
	}

	// Below 20 findings: load active notifiers once for the batch instead of N database queries (D69)
	connectors, err := r.store.ListConnectors(ctx, tenantID)
	if err != nil {
		return []error{fmt.Errorf("router: failed to list connectors: %w", err)}
	}

	type activeTarget struct {
		name     string
		routing  *domain.NotificationRoutingRule
		notifier Notifier
	}

	var allErrs []error
	var targets []activeTarget
	for _, conn := range connectors {
		if !conn.IsConnected() && conn.GetCondition("Connected") != nil && conn.GetCondition("Connected").Status == "False" {
			continue
		}
		notifier, err := r.buildNotifier(ctx, tenantID, conn)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("connector %q build error: %w", conn.Name, err))
			continue
		}
		if notifier != nil {
			targets = append(targets, activeTarget{
				name:     conn.Name,
				routing:  conn.Spec.Routing,
				notifier: notifier,
			})
		}
	}

	for _, f := range findings {
		msg := NotificationMessage{
			ID:        uuid.New().String(),
			TenantID:  tenantID.String(),
			AppName:   appName,
			Title:     f.Title,
			Summary:   f.Description,
			Severity:  strings.ToLower(string(f.Severity)),
			FindingID: f.ID.String(),
			URL:       fmt.Sprintf("%s/t/%s/findings/%s", r.publicURL, tenantID.String(), f.ID.String()),
			Timestamp: time.Now().UTC(),
		}
		for _, tgt := range targets {
			if !matchesRouting(tgt.routing, msg) {
				continue
			}
			if err := tgt.notifier.Send(ctx, msg); err != nil {
				allErrs = append(allErrs, fmt.Errorf("connector %q send failed: %w", tgt.name, err))
			}
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
		if conn.Spec.Slack.TokenSecretRef.Name != "" {
			if r.secretResolver == nil {
				return nil, fmt.Errorf("connector %q requires secretResolver for token %q", conn.Name, conn.Spec.Slack.TokenSecretRef.Name)
			}
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Slack.TokenSecretRef.Key)
			b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			if err != nil {
				return nil, fmt.Errorf("connector %q failed to resolve token secret %q: %w", conn.Name, conn.Spec.Slack.TokenSecretRef.Name, err)
			}
			if len(b) == 0 {
				return nil, fmt.Errorf("connector %q token secret %q exists but value is empty", conn.Name, conn.Spec.Slack.TokenSecretRef.Name)
			}
			token = string(b)
		}
		return NewSlackNotifier(r.client, token, conn.Spec.Slack.DefaultChannel), nil

	case domain.ConnectorTypeTeams:
		if conn.Spec.Teams == nil {
			return nil, nil
		}
		webhookURL := ""
		if conn.Spec.Teams.WebhookSecretRef.Name != "" {
			if r.secretResolver == nil {
				return nil, fmt.Errorf("connector %q requires secretResolver for webhook %q", conn.Name, conn.Spec.Teams.WebhookSecretRef.Name)
			}
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Teams.WebhookSecretRef.Key)
			b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			if err != nil {
				return nil, fmt.Errorf("connector %q failed to resolve webhook URL secret %q: %w", conn.Name, conn.Spec.Teams.WebhookSecretRef.Name, err)
			}
			if len(b) == 0 {
				return nil, fmt.Errorf("connector %q webhook URL secret %q exists but value is empty", conn.Name, conn.Spec.Teams.WebhookSecretRef.Name)
			}
			webhookURL = string(b)
		}
		return NewTeamsNotifier(r.client, webhookURL), nil

	case domain.ConnectorTypeWebhook:
		if conn.Spec.Webhook == nil {
			return nil, nil
		}
		var secret []byte
		if conn.Spec.Webhook.SecretRef.Name != "" {
			if r.secretResolver == nil {
				return nil, fmt.Errorf("connector %q requires secretResolver for secretRef %q", conn.Name, conn.Spec.Webhook.SecretRef.Name)
			}
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Webhook.SecretRef.Key)
			b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			if err != nil {
				return nil, fmt.Errorf("connector %q failed to resolve HMAC secret %q: %w", conn.Name, conn.Spec.Webhook.SecretRef.Name, err)
			}
			if len(b) == 0 {
				return nil, fmt.Errorf("connector %q HMAC secret %q exists but value is empty", conn.Name, conn.Spec.Webhook.SecretRef.Name)
			}
			secret = b
		}
		return NewWebhookNotifier(r.client, conn.Spec.Webhook.URL, secret, conn.Spec.Webhook.Format, conn.Spec.Webhook.Headers), nil

	case domain.ConnectorTypeEmail:
		if conn.Spec.Email == nil {
			return nil, nil
		}
		username, password := "", ""
		if conn.Spec.Email.SMTP.CredentialsSecretRef.Name != "" {
			if r.secretResolver == nil {
				return nil, fmt.Errorf("connector %q requires secretResolver for SMTP credentials %q", conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Name)
			}
			secKey := fmt.Sprintf("connector:%s:%s", conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Key)
			b, err := r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			if err != nil {
				return nil, fmt.Errorf("connector %q failed to resolve SMTP credentials %q: %w", conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Name, err)
			}
			if len(b) == 0 {
				return nil, fmt.Errorf("connector %q SMTP credentials secret %q exists but value is empty", conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Name)
			}
			parts := strings.SplitN(string(b), ":", 2)
			if len(parts) == 2 {
				username, password = parts[0], parts[1]
			}
		}
		return NewEmailNotifier(conn.Spec.Email.SMTP, conn.Spec.Email.From, conn.Spec.Email.To, username, password), nil

	default:
		return nil, nil
	}
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func matchesRouting(rule *domain.NotificationRoutingRule, msg NotificationMessage) bool {
	if rule == nil {
		return true
	}
	// 1. Min severity
	if rule.MinSeverity != "" {
		if severityRank(msg.Severity) < severityRank(string(rule.MinSeverity)) {
			return false
		}
	}
	// 2. Application filter
	if len(rule.Applications) > 0 && msg.AppName != "" {
		matched := false
		for _, app := range rule.Applications {
			if strings.EqualFold(app, msg.AppName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
