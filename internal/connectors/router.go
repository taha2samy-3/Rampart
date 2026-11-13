package connectors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/secrets"
	"rampart/internal/store"
)

// SecretResolver resolves stored secret material for a connector.
type SecretResolver interface {
	GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error)
}

// DecryptingSecretResolver wraps a SecretResolver and transparently decrypts ciphertext
// using the provided secrets.Cipher when configured (D4, D49, D69).
type DecryptingSecretResolver struct {
	Inner  SecretResolver
	Cipher *secrets.Cipher
}

// NewDecryptingSecretResolver creates a new DecryptingSecretResolver.
func NewDecryptingSecretResolver(inner SecretResolver, cipher *secrets.Cipher) *DecryptingSecretResolver {
	return &DecryptingSecretResolver{Inner: inner, Cipher: cipher}
}

// GetSecretMaterial retrieves and decrypts the secret material for key.
func (d *DecryptingSecretResolver) GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error) {
	if d.Inner == nil {
		return nil, errors.New("inner secret resolver is nil")
	}
	raw, err := d.Inner.GetSecretMaterial(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if d.Cipher != nil && len(raw) > 0 {
		decrypted, err := d.Cipher.Decrypt(tenantID, key, raw)
		if err == nil {
			return decrypted, nil
		}
	}
	return raw, nil
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

// RouteInAppNotification dispatches an in-app notification (D45) to all active connectors.
func (r *NotificationRouter) RouteInAppNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) []error {
	if n == nil {
		return nil
	}
	url := ""
	if r.publicURL != "" && n.Link != "" {
		if strings.HasPrefix(n.Link, "/") {
			url = r.publicURL + n.Link
		} else {
			url = r.publicURL + "/" + n.Link
		}
	}
	sev := "medium"
	switch n.Kind {
	case domain.NotifySLABreached:
		sev = "high"
	case domain.NotifyAcceptanceEnding:
		sev = "low"
	}
	msg := NotificationMessage{
		ID:        n.ID.String(),
		TenantID:  tenantID.String(),
		Title:     n.Title,
		Summary:   n.Body,
		Severity:  sev,
		URL:       url,
		Timestamp: n.CreatedAt,
		Fields:    map[string]string{"event": n.Kind},
	}
	return r.RouteNotification(ctx, tenantID, msg)
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

		digestURL := ""
		if r.publicURL != "" && len(findings) > 0 && findings[0].ApplicationID != uuid.Nil {
			digestURL = fmt.Sprintf("%s/applications/%s", r.publicURL, findings[0].ApplicationID.String())
		}
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
			Fields:      map[string]string{"event": "digest"},
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
		if cond := conn.GetCondition("Ready"); cond != nil && cond.Status == "False" {
			continue
		}
		if cond := conn.GetCondition("Connected"); cond != nil && cond.Status == "False" {
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

	tenantSlug := tenantID.String()
	if r.store != nil {
		if t, err := r.store.GetTenant(ctx, tenantID); err == nil && t != nil && t.Slug != "" {
			tenantSlug = t.Slug
		}
	}

	for _, f := range findings {
		findingURL := ""
		if r.publicURL != "" {
			findingURL = fmt.Sprintf("%s/t/%s/findings/%s", r.publicURL, tenantSlug, f.ID.String())
		}
		msg := NotificationMessage{
			ID:        uuid.New().String(),
			TenantID:  tenantID.String(),
			AppName:   appName,
			Title:     f.Title,
			Summary:   f.Description,
			Severity:  strings.ToLower(string(f.Severity)),
			FindingID: f.ID.String(),
			URL:       findingURL,
			Timestamp: time.Now().UTC(),
			Fields:    map[string]string{"event": "finding_created"},
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
			secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Slack.TokenSecretRef.Key)
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
			secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Teams.WebhookSecretRef.Key)
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
			secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Webhook.SecretRef.Key)
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
			// 1. Check separate username and password keys
			userKey := fmt.Sprintf("connector:%s:username", conn.Name)
			passKey := fmt.Sprintf("connector:%s:password", conn.Name)
			uBytes, errU := r.secretResolver.GetSecretMaterial(ctx, tenantID, userKey)
			pBytes, errP := r.secretResolver.GetSecretMaterial(ctx, tenantID, passKey)
			if errU == nil && errP == nil && len(pBytes) > 0 {
				username = string(uBytes)
				password = string(pBytes)
			} else {
				// 2. Fall back to combined key (e.g. key "token", "password", or "credentials")
				secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Email.SMTP.CredentialsSecretRef.Key)
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
				} else {
					password = string(b)
				}
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
	case "info":
		return 0
	default:
		return -1 // Unrecognized or misspelled severities rank below info
	}
}

func matchesRouting(rule *domain.NotificationRoutingRule, msg NotificationMessage) bool {
	if rule == nil {
		return true
	}
	// 1. Min severity
	if rule.MinSeverity != "" {
		targetRank := severityRank(string(rule.MinSeverity))
		msgRank := severityRank(msg.Severity)
		if targetRank == -1 || msgRank < targetRank {
			return false
		}
	}
	// 2. Application filter (matches application name or application slug)
	if len(rule.Applications) > 0 {
		matched := false
		for _, app := range rule.Applications {
			if msg.AppName != "" && strings.EqualFold(app, msg.AppName) {
				matched = true
				break
			}
			if msg.Fields != nil && msg.Fields["appSlug"] != "" && strings.EqualFold(app, msg.Fields["appSlug"]) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 3. Events filter
	if len(rule.Events) > 0 {
		event := ""
		if msg.Fields != nil {
			event = msg.Fields["event"]
		}
		if event == "" {
			return false
		}
		matched := false
		for _, ev := range rule.Events {
			if strings.EqualFold(ev, event) {
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
