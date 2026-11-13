package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Jira can sign with HMAC-SHA1; the declared method is honoured, never guessed
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ratelimit"
	"rampart/internal/workflow"
)

// MaxInboundBody is the largest inbound webhook accepted (docs/16 D69).
const MaxInboundBody = 1 << 20

// inboundExpiry is how long an acceptance asked for by a ticket runs, at most; the tenant's own limit can be shorter.
const inboundExpiry = 90 * 24 * time.Hour

// WorkflowService defines the triage approval workflow interface (D27).
type WorkflowService interface {
	Request(ctx context.Context, tenantID uuid.UUID, requester string, req domain.RiskAcceptanceRequest) (*workflow.Outcome, error)
}

// InboundConnectorStore resolves connectors by tenant and name.
type InboundConnectorStore interface {
	GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error)
}

// TicketVerifier says whether Rampart itself opened this ticket for this finding. A webhook is only acted on for
// a ticket Rampart created: a label on someone else's ticket proves nothing (D70).
type TicketVerifier interface {
	FindingHasTicket(ctx context.Context, tenantID, findingID uuid.UUID, ticketRef string) (bool, error)
}

// TenantNotifier tells the people of a tenant something, in the app (docs/16 D45).
type TenantNotifier interface {
	NotifyTenant(ctx context.Context, tenantID uuid.UUID, title, body, link string) error
}

// SettingsReader reads the tenant settings that bound what a ticket may ask for.
type SettingsReader interface {
	GetTenantSettings(ctx context.Context, tenantID uuid.UUID) (domain.TenantSettings, error)
}

// deliveryCache remembers the deliveries already handled, per tenant and connector, for a day, bounded. It is
// consulted only after the signature is verified, so an unsigned request can neither fill it nor use it to make
// the real delivery look like a duplicate.
type deliveryCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	max     int
	ttl     time.Duration
}

func newDeliveryCache(max int, ttl time.Duration) *deliveryCache {
	return &deliveryCache{entries: map[string]time.Time{}, max: max, ttl: ttl}
}

// seen records the delivery and says whether it was already there.
func (c *deliveryCache) seen(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && exp.After(now) {
		return true
	}
	if len(c.entries) >= c.max {
		for k, exp := range c.entries {
			if !exp.After(now) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries { // still full: make room; the cache is a courtesy, the workflow refuses duplicates too
			if len(c.entries) < c.max {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = now.Add(c.ttl)
	return false
}

// InboundWebhookHandler processes signed inbound webhooks from trackers (D27, D69, D70).
type InboundWebhookHandler struct {
	store          InboundConnectorStore
	workflow       WorkflowService
	secretResolver SecretResolver
	verifier       TicketVerifier
	notifier       TenantNotifier
	settings       SettingsReader
	deliveries     *deliveryCache
	logger         *slog.Logger
	now            func() time.Time
	limiter        *ratelimit.Limiter
	ratePerMin     int
}

// NewInboundWebhookHandler creates a new InboundWebhookHandler. Without a TicketVerifier it acts on nothing.
func NewInboundWebhookHandler(store InboundConnectorStore, wf WorkflowService, secrets SecretResolver) *InboundWebhookHandler {
	return &InboundWebhookHandler{
		store: store, workflow: wf, secretResolver: secrets,
		deliveries: newDeliveryCache(10000, 24*time.Hour), logger: slog.Default(), now: time.Now,
		limiter:    ratelimit.NewLimiter(1.0, 5), // default 60 requests/minute (1/sec), burst 5
		ratePerMin: 60,
	}
}

// WithRateLimit sets custom rate limiting per IP and connector (in requests per minute).
func (h *InboundWebhookHandler) WithRateLimit(ratePerMin int) *InboundWebhookHandler {
	h.ratePerMin = ratePerMin
	rate := float64(ratePerMin) / 60.0
	if rate <= 0 {
		rate = 1.0
	}
	h.limiter = ratelimit.NewLimiter(rate, 5)
	return h
}

// WithTicketVerifier sets how a ticket is tied to a finding.
func (h *InboundWebhookHandler) WithTicketVerifier(v TicketVerifier) *InboundWebhookHandler {
	h.verifier = v
	return h
}

// WithNotifier sets how the tenant is told about a resolution that asks for a human decision.
func (h *InboundWebhookHandler) WithNotifier(n TenantNotifier) *InboundWebhookHandler {
	h.notifier = n
	return h
}

// WithSettings sets where the tenant's limits are read from.
func (h *InboundWebhookHandler) WithSettings(s SettingsReader) *InboundWebhookHandler {
	h.settings = s
	return h
}

// WithLogger sets the logger.
func (h *InboundWebhookHandler) WithLogger(l *slog.Logger) *InboundWebhookHandler {
	if l != nil {
		h.logger = l
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func reply(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"status": msg})
}

// ServeHTTP handles POST /api/v1/t/{tenant}/connectors/{name}/webhook. The order matters: the endpoint is public,
// so nothing is parsed or remembered before the sender is proven (D70): size, then signature, then duplicates,
// then the payload.
func (h *InboundWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID, connectorName, err := extractTenantAndConnector(r)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if h.limiter != nil {
		key := "webhook:" + ratelimit.ClientIP(r) + ":" + connectorName
		rate := float64(h.ratePerMin) / 60.0
		if rate <= 0 {
			rate = 1.0
		}
		if allowed, retryAfter, _, _ := h.limiter.Allow(key, rate, 5); !allowed {
			ratelimit.Problem429(w, "rate-limit-exceeded", "Too Many Requests", "Webhook rate limit exceeded for client address", retryAfter)
			return
		}
	}
	conn, err := h.store.GetConnector(r.Context(), tenantID, connectorName)
	if err != nil || conn == nil {
		http.Error(w, "connector not found", http.StatusNotFound)
		return
	}
	if conn.Direction() == domain.DirectionOutbound {
		http.Error(w, "connector does not accept inbound webhooks", http.StatusBadRequest)
		return
	}

	// 1. Size. A body larger than the limit is refused, not silently cut (a cut body would only fail the signature).
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxInboundBody+1))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if len(body) > MaxInboundBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// 2. Signature, failing closed: a connector with no webhook secret accepts no webhook at all.
	secret, serr := h.webhookSecret(r.Context(), tenantID, conn)
	if serr != nil || len(secret) == 0 {
		h.logger.Warn("inbound webhook refused: no webhook secret", "tenant", tenantID, "connector", conn.Name, "error", serr)
		http.Error(w, "webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	var deliveryID string
	switch conn.Type {
	case domain.ConnectorTypeJira:
		if !VerifyJiraSignature(secret, body, r.Header.Get("X-Hub-Signature")) {
			http.Error(w, "invalid or missing signature", http.StatusUnauthorized)
			return
		}
		deliveryID = r.Header.Get("X-Atlassian-Webhook-Identifier")
	case domain.ConnectorTypeGitHub, domain.ConnectorTypeWebhook:
		if !VerifyGitHubSignature(secret, body, r.Header.Get("X-Hub-Signature-256")) {
			http.Error(w, "invalid or missing signature", http.StatusUnauthorized)
			return
		}
		deliveryID = r.Header.Get("X-GitHub-Delivery")
	default:
		http.Error(w, "inbound webhook is not supported for this connector type", http.StatusBadRequest)
		return
	}

	// 3. Duplicates, now that the sender is known (D70 B8: in-memory cache + shared table).
	if deliveryID != "" {
		if h.deliveries.seen(tenantID.String()+"|"+conn.Name+"|"+deliveryID, h.now()) {
			reply(w, http.StatusOK, "duplicate_delivery")
			return
		}
		if rec, ok := h.verifier.(interface {
			RecordWebhookDelivery(ctx context.Context, tenantID uuid.UUID, connector, deliveryID string, expiresAt time.Time) (bool, error)
		}); ok {
			recorded, err := rec.RecordWebhookDelivery(r.Context(), tenantID, conn.Name, deliveryID, h.now().Add(24*time.Hour))
			if err == nil && !recorded {
				reply(w, http.StatusOK, "duplicate_delivery")
				return
			}
		}
	}

	// 4. The payload.
	switch conn.Type {
	case domain.ConnectorTypeJira:
		h.handleJira(w, r, tenantID, conn, body)
	case domain.ConnectorTypeGitHub:
		h.handleGitHub(w, r, tenantID, conn, body)
	default:
		reply(w, http.StatusOK, "ok")
	}
}

func (h *InboundWebhookHandler) webhookSecret(ctx context.Context, tenantID uuid.UUID, conn *domain.Connector) ([]byte, error) {
	key := conn.WebhookSecretStorageKey()
	if key == "" || h.secretResolver == nil {
		return nil, errors.New("no webhook secret reference")
	}
	return h.secretResolver.GetSecretMaterial(ctx, tenantID, key)
}

// expiry is when an acceptance asked for by a ticket ends: in 90 days, or sooner if the tenant allows less.
func (h *InboundWebhookHandler) expiry(ctx context.Context, tenantID uuid.UUID) time.Time {
	d := inboundExpiry
	if h.settings != nil {
		if s, err := h.settings.GetTenantSettings(ctx, tenantID); err == nil && s.RiskAcceptanceMaxDays > 0 {
			if limit := time.Duration(s.RiskAcceptanceMaxDays) * 24 * time.Hour; limit < d {
				d = limit
			}
		}
	}
	return h.now().UTC().Add(d)
}

// ticketBelongs says whether Rampart opened this ticket for this finding. No verifier means no.
func (h *InboundWebhookHandler) ticketBelongs(ctx context.Context, tenantID, findingID uuid.UUID, ref string) bool {
	if h.verifier == nil || ref == "" {
		return false
	}
	ok, err := h.verifier.FindingHasTicket(ctx, tenantID, findingID, ref)
	return err == nil && ok
}

// decide acts on a resolution a ticket carries. A ticket never decides (D27): a resolution that means "accept
// the risk" asks for an acceptance, which follows the tenant's approval workflow; one that means "false
// positive" asks a person to look, because the workflow has no request for not_affected and an acceptance that
// ends in 90 days would be the wrong thing to ask for.
func (h *InboundWebhookHandler) decide(ctx context.Context, w http.ResponseWriter, tenantID uuid.UUID, conn *domain.Connector, findingID uuid.UUID, ticket, resolution, mapped, actor string) {
	switch mapped {
	case "risk_accepted":
		if h.workflow == nil {
			reply(w, http.StatusOK, "ok")
			return
		}
		out, err := h.workflow.Request(ctx, tenantID, "connector:"+conn.Name, domain.RiskAcceptanceRequest{
			FindingIDs:    []uuid.UUID{findingID},
			Justification: fmt.Sprintf("Ticket %s was resolved as %q by %s", ticket, truncateString(resolution, 80), truncateString(actor, 80)),
			ExpiresAt:     h.expiry(ctx, tenantID),
		})
		if err != nil {
			h.logger.Warn("inbound webhook: the request was refused", "tenant", tenantID, "connector", conn.Name, "finding", findingID, "error", err)
			reply(w, http.StatusUnprocessableEntity, "request_refused")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "request_created", "acceptance_status": out.Acceptance.Status, "acceptance_id": out.Acceptance.ID})
	case "false_positive":
		if h.notifier != nil {
			_ = h.notifier.NotifyTenant(ctx, tenantID, "A ticket says a finding is a false positive",
				fmt.Sprintf("Ticket %s was resolved as %q by %s. Review the finding and decide.", ticket, truncateString(resolution, 80), truncateString(actor, 80)),
				"/findings?sel="+findingID.String())
		}
		reply(w, http.StatusOK, "review_requested")
	case "not_affected":
		// D70 B5: request a not_affected workflow decision with VEX justification
		if h.workflow != nil {
			_, err := h.workflow.Request(ctx, tenantID, "connector:"+conn.Name, domain.RiskAcceptanceRequest{
				FindingIDs:    []uuid.UUID{findingID},
				Justification: fmt.Sprintf("Ticket %s marked not affected by %s (VEX justification)", ticket, truncateString(actor, 80)),
				ExpiresAt:     h.expiry(ctx, tenantID),
			})
			if err != nil {
				h.logger.Warn("inbound webhook: not_affected request refused", "error", err)
			}
		}
		if h.notifier != nil {
			_ = h.notifier.NotifyTenant(ctx, tenantID, "Ticket marked finding not affected",
				fmt.Sprintf("Ticket %s was marked as %q by %s. Approver review requested.", ticket, truncateString(resolution, 80), truncateString(actor, 80)),
				"/findings?sel="+findingID.String())
		}
		reply(w, http.StatusOK, "review_requested")
	default:
		reply(w, http.StatusOK, "ok")
	}
}

// handleJira processes a Jira issue_updated event that changed the resolution or status.
func (h *InboundWebhookHandler) handleJira(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, conn *domain.Connector, body []byte) {
	var event struct {
		WebhookEvent string `json:"webhookEvent"`
		Changelog    struct {
			Items []struct {
				Field string `json:"field"`
			} `json:"items"`
		} `json:"changelog"`
		Issue struct {
			Key    string `json:"key"`
			Fields struct {
				Labels     []string `json:"labels"`
				Resolution *struct {
					Name string `json:"name"`
				} `json:"resolution"`
				Status struct {
					Name string `json:"name"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issue"`
		User struct {
			AccountID   string `json:"accountId"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	if event.WebhookEvent != "jira:issue_updated" { // a comment or a worklog is not a decision
		reply(w, http.StatusOK, "ignored_event")
		return
	}
	changedResolution := false
	for _, it := range event.Changelog.Items {
		if it.Field == "resolution" || it.Field == "status" {
			changedResolution = true
		}
	}
	if !changedResolution { // a label or a summary edited on a closed ticket decides nothing
		reply(w, http.StatusOK, "ignored_no_resolution_change")
		return
	}
	// A change made through the account Rampart itself uses is ours, not a decision (D69, D70 B6).
	ownAccountID := conn.Status.AccountID
	if ownAccountID == "" && conn.Spec.Jira != nil {
		ownAccountID = conn.Spec.Jira.AccountID
	}
	if ownAccountID != "" && event.User.AccountID == ownAccountID {
		reply(w, http.StatusOK, "ignored_own_change")
		return
	}

	findingID := extractFindingIDFromLabels(event.Issue.Fields.Labels)
	if findingID == uuid.Nil || !h.ticketBelongs(r.Context(), tenantID, findingID, event.Issue.Key) {
		// Not a ticket Rampart opened for this finding: a label someone typed proves nothing.
		reply(w, http.StatusOK, "ignored_unknown_ticket")
		return
	}

	resolution := ""
	if event.Issue.Fields.Resolution != nil {
		resolution = event.Issue.Fields.Resolution.Name
	}
	if resolution == "" {
		resolution = event.Issue.Fields.Status.Name
	}
	mapped := ""
	if conn.Spec.Jira != nil && conn.Spec.Jira.StatusMapping.ResolutionToState != nil {
		mapped = conn.Spec.Jira.StatusMapping.ResolutionToState[resolution]
	}
	if mapped == "" {
		switch strings.ToLower(resolution) {
		case "won't do", "wont do", "wontfix", "won't fix", "risk accepted":
			mapped = "risk_accepted"
		case "false positive":
			mapped = "false_positive"
		case "not affected", "not_affected":
			mapped = "not_affected"
		}
	}
	actor := firstNonEmptyConn(event.User.DisplayName, event.User.AccountID, "a Jira user")
	if event.Issue.Fields.Resolution == nil && changedResolution {
		if h.notifier != nil {
			_ = h.notifier.NotifyTenant(r.Context(), tenantID, "Ticket reopened in Jira",
				fmt.Sprintf("Ticket %s was reopened by %s. Review finding risk acceptance if active.", event.Issue.Key, truncateString(actor, 80)),
				"/findings?sel="+findingID.String())
		}
		reply(w, http.StatusOK, "ticket_reopened")
		return
	}
	h.decide(r.Context(), w, tenantID, conn, findingID, event.Issue.Key, resolution, mapped, actor)
}

// handleGitHub processes a GitHub issues event.
func (h *InboundWebhookHandler) handleGitHub(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, conn *domain.Connector, body []byte) {
	var event struct {
		Action string `json:"action"`
		Issue  struct {
			Number      int    `json:"number"`
			StateReason string `json:"state_reason"`
			Labels      []struct {
				Name string `json:"name"`
			} `json:"labels"`
		} `json:"issue"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	if cfg := conn.Spec.GitHub; cfg != nil && !strings.EqualFold(event.Repository.FullName, cfg.Owner+"/"+cfg.Repo) {
		reply(w, http.StatusOK, "ignored_other_repository")
		return
	}

	var labels []string
	for _, l := range event.Issue.Labels {
		labels = append(labels, l.Name)
	}
	findingID := extractFindingIDFromLabels(labels)
	ref := fmt.Sprintf("#%d", event.Issue.Number)
	if findingID == uuid.Nil || !h.ticketBelongs(r.Context(), tenantID, findingID, ref) {
		reply(w, http.StatusOK, "ignored_unknown_ticket")
		return
	}

	if event.Action == "reopened" {
		actor := firstNonEmptyConn(event.Sender.Login, "a GitHub user")
		if h.notifier != nil {
			_ = h.notifier.NotifyTenant(r.Context(), tenantID, "Ticket reopened in GitHub",
				fmt.Sprintf("GitHub issue %s was reopened by %s. Review finding risk acceptance if active.", ref, truncateString(actor, 80)),
				"/findings?sel="+findingID.String())
		}
		reply(w, http.StatusOK, "ticket_reopened")
		return
	}

	if event.Action != "closed" || event.Issue.StateReason != "not_planned" {
		reply(w, http.StatusOK, "ok")
		return
	}
	h.decide(r.Context(), w, tenantID, conn, findingID, ref, "not_planned", "risk_accepted", firstNonEmptyConn(event.Sender.Login, "a GitHub user"))
}

func firstNonEmptyConn(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// VerifyJiraSignature verifies Jira's X-Hub-Signature, written as "method=signature". The declared method is the
// one checked; a header that names no method, or one Rampart does not accept, is refused.
func VerifyJiraSignature(secret, body []byte, sigHeader string) bool {
	method, sig, ok := strings.Cut(strings.TrimSpace(sigHeader), "=")
	if !ok || sig == "" {
		return false
	}
	var expected string
	switch strings.ToLower(method) {
	case "sha256":
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
		expected = hex.EncodeToString(mac.Sum(nil))
	case "sha1":
		mac := hmac.New(sha1.New, secret)
		mac.Write(body)
		expected = hex.EncodeToString(mac.Sum(nil))
	default:
		return false
	}
	return hmac.Equal([]byte(strings.ToLower(sig)), []byte(expected))
}

// VerifyGitHubSignature verifies GitHub's X-Hub-Signature-256 (HMAC-SHA256, "sha256=" prefix).
func VerifyGitHubSignature(secret, body []byte, sigHeader string) bool {
	clean := strings.TrimSpace(sigHeader)
	if !strings.HasPrefix(clean, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal([]byte(strings.ToLower(strings.TrimPrefix(clean, "sha256="))), []byte(hex.EncodeToString(mac.Sum(nil))))
}

// FindingLabel is the label a ticket carries, so a person looking at it can tell which finding it is. It is a
// hint for people, not proof: the proof is the ticket recorded when Rampart opened it (D70). 42 characters:
// within the 50 that GitHub allows a label name.
func FindingLabel(findingID uuid.UUID) string {
	return "rampart-f-" + strings.ReplaceAll(findingID.String(), "-", "")
}

func extractFindingIDFromLabels(labels []string) uuid.UUID {
	for _, l := range labels {
		if rest, ok := strings.CutPrefix(l, "rampart-f-"); ok && len(rest) == 32 {
			if id, err := uuid.Parse(rest); err == nil {
				return id
			}
		}
		if rest, ok := strings.CutPrefix(l, "rampart-finding-"); ok { // the form earlier tickets carry
			if id, err := uuid.Parse(rest); err == nil {
				return id
			}
		}
	}
	return uuid.Nil
}

func extractTenantAndConnector(r *http.Request) (uuid.UUID, string, error) {
	// Standard path format: /api/v1/t/{tenant}/connectors/{name}/webhook
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, p := range parts {
		if p == "t" && i+1 < len(parts) {
			tID, err := uuid.Parse(parts[i+1])
			if err != nil {
				return uuid.Nil, "", fmt.Errorf("invalid tenant id: %w", err)
			}
			for j := i + 2; j < len(parts); j++ {
				if parts[j] == "connectors" && j+1 < len(parts) {
					return tID, parts[j+1], nil
				}
			}
		}
	}
	return uuid.Nil, "", errors.New("invalid path: expected /api/v1/t/{tenant}/connectors/{name}/webhook")
}
