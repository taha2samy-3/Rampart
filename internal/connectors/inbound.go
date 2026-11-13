package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/workflow"
)

// WorkflowService defines the triage approval workflow interface (Milestone 3.2, D27).
type WorkflowService interface {
	Request(ctx context.Context, tenantID uuid.UUID, requester string, req domain.RiskAcceptanceRequest) (*workflow.Outcome, error)
}

// InboundConnectorStore resolves connectors by tenant and name.
type InboundConnectorStore interface {
	GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error)
}

// InboundWebhookHandler processes signed inbound webhooks from trackers and services (D27, D69).
type InboundWebhookHandler struct {
	store          InboundConnectorStore
	workflow       WorkflowService
	secretResolver SecretResolver
	deliveryCache  sync.Map // deduplication: deliveryID -> time.Time
}

// NewInboundWebhookHandler creates a new InboundWebhookHandler.
func NewInboundWebhookHandler(store InboundConnectorStore, wf WorkflowService, secrets SecretResolver) *InboundWebhookHandler {
	return &InboundWebhookHandler{
		store:          store,
		workflow:       wf,
		secretResolver: secrets,
	}
}

// ServeHTTP handles POST requests to /api/v1/t/{tenant}/connectors/{name}/webhook.
func (h *InboundWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Extract tenant and connector name from URL path
	tenantID, connectorName, err := extractTenantAndConnector(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Load connector configuration
	conn, err := h.store.GetConnector(r.Context(), tenantID, connectorName)
	if err != nil || conn == nil {
		http.Error(w, "connector not found", http.StatusNotFound)
		return
	}

	// Connector must admit inbound deliveries
	if conn.Direction() == domain.DirectionOutbound {
		http.Error(w, "connector does not accept inbound webhooks (direction is outbound only)", http.StatusBadRequest)
		return
	}

	// 3. Size limit (D69: 1 MiB max inbound webhook payload)
	limitedReader := io.LimitReader(r.Body, 1<<20)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	switch conn.Type {
	case domain.ConnectorTypeJira:
		h.handleJiraWebhook(w, r, tenantID, conn, body)
	case domain.ConnectorTypeGitHub:
		h.handleGitHubWebhook(w, r, tenantID, conn, body)
	case domain.ConnectorTypeWebhook:
		h.handleGenericWebhook(w, r, tenantID, conn, body)
	default:
		http.Error(w, fmt.Sprintf("inbound webhook not supported for connector type %s", conn.Type), http.StatusBadRequest)
	}
}

// handleJiraWebhook processes Jira Cloud/DC issue_updated events.
func (h *InboundWebhookHandler) handleJiraWebhook(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, conn *domain.Connector, body []byte) {
	// Deduplicate delivery
	deliveryID := r.Header.Get("X-Atlassian-Webhook-Identifier")
	if deliveryID != "" {
		if _, seen := h.deliveryCache.LoadOrStore(deliveryID, time.Now()); seen {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"duplicate_delivery"}`))
			return
		}
	}

	// Signature verification (D69)
	sigHeader := r.Header.Get("X-Hub-Signature")
	if sigHeader == "" {
		sigHeader = r.Header.Get("X-Hub-Signature-256")
	}

	var secretBytes []byte
	if conn.Spec.Jira != nil && conn.Spec.Jira.CredentialsSecretRef.Name != "" && h.secretResolver != nil {
		secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Jira.CredentialsSecretRef.Key)
		if conn.Spec.Jira.CredentialsSecretRef.Key == "" {
			secKey = domain.ConnectorSecretStorageKey(conn.Name, "apiToken")
		}
		secretBytes, _ = h.secretResolver.GetSecretMaterial(r.Context(), tenantID, secKey)
	}

	if len(secretBytes) > 0 {
		if sigHeader == "" || !VerifyJiraSignature(secretBytes, body, sigHeader) {
			http.Error(w, "invalid or missing webhook signature", http.StatusUnauthorized)
			return
		}
	}

	var event struct {
		WebhookEvent string `json:"webhookEvent"`
		Issue        struct {
			ID     string `json:"id"`
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

	// Find associated finding ID from labels: rampart-finding-<uuid>
	findingID := extractFindingIDFromLabels(event.Issue.Fields.Labels)
	if findingID == uuid.Nil {
		// Not a Rampart-managed issue or finding ID not encoded
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ignored_no_finding_label"}`))
		return
	}

	resolutionName := ""
	if event.Issue.Fields.Resolution != nil {
		resolutionName = event.Issue.Fields.Resolution.Name
	}
	if resolutionName == "" {
		resolutionName = event.Issue.Fields.Status.Name
	}

	// Check mapping: e.g. "Won't Do", "False Positive", "Risk Accepted"
	mappedState := ""
	if conn.Spec.Jira != nil && conn.Spec.Jira.StatusMapping.ResolutionToState != nil {
		mappedState = conn.Spec.Jira.StatusMapping.ResolutionToState[resolutionName]
	}
	if mappedState == "" {
		switch strings.ToLower(resolutionName) {
		case "won't do", "wont do", "wontfix", "won't fix", "risk accepted":
			mappedState = "risk_accepted"
		case "false positive":
			mappedState = "false_positive"
		}
	}

	// CRITICAL RULE (D27): A ticket never decides. A resolution mapped to risk_accepted or not_affected
	// creates a REQUEST in the approval workflow, never mutates state directly.
	if (mappedState == "risk_accepted" || mappedState == "false_positive") && h.workflow != nil {
		actor := event.User.DisplayName
		if actor == "" {
			actor = event.User.AccountID
		}
		if actor == "" {
			actor = "jira-user"
		}

		req := domain.RiskAcceptanceRequest{
			FindingIDs:    []uuid.UUID{findingID},
			Justification: fmt.Sprintf("External Jira resolution: %q on %s by %s", resolutionName, event.Issue.Key, actor),
			ExpiresAt:     time.Now().UTC().AddDate(0, 3, 0), // 90-day review period
		}
		requester := fmt.Sprintf("connector:%s", conn.Name)
		outcome, err := h.workflow.Request(r.Context(), tenantID, requester, req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to submit risk acceptance request: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":            "request_created",
			"ticket_key":        event.Issue.Key,
			"mapped_state":      mappedState,
			"acceptance_status": outcome.Acceptance.Status,
			"acceptance_id":     outcome.Acceptance.ID,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleGitHubWebhook processes GitHub issues events.
func (h *InboundWebhookHandler) handleGitHubWebhook(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, conn *domain.Connector, body []byte) {
	deliveryID := r.Header.Get("X-GitHub-Delivery")
	if deliveryID != "" {
		if _, seen := h.deliveryCache.LoadOrStore(deliveryID, time.Now()); seen {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"duplicate_delivery"}`))
			return
		}
	}

	sigHeader := r.Header.Get("X-Hub-Signature-256")
	var secretBytes []byte
	if conn.Spec.GitHub != nil && conn.Spec.GitHub.CredentialsSecretRef.Name != "" && h.secretResolver != nil {
		secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.GitHub.CredentialsSecretRef.Key)
		secretBytes, _ = h.secretResolver.GetSecretMaterial(r.Context(), tenantID, secKey)
	}

	if len(secretBytes) > 0 {
		if sigHeader == "" || !VerifyGitHubSignature(secretBytes, body, sigHeader) {
			http.Error(w, "invalid or missing github signature", http.StatusUnauthorized)
			return
		}
	}

	var event struct {
		Action string `json:"action"` // closed, labeled, edited
		Issue  struct {
			Number      int    `json:"number"`
			State       string `json:"state"`
			StateReason string `json:"state_reason"` // "not_planned", "completed"
			Labels      []struct {
				Name string `json:"name"`
			} `json:"labels"`
		} `json:"issue"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}

	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	var labelNames []string
	for _, l := range event.Issue.Labels {
		labelNames = append(labelNames, l.Name)
	}
	findingID := extractFindingIDFromLabels(labelNames)
	if findingID == uuid.Nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ignored_no_finding_label"}`))
		return
	}

	// D27: If closed with "not_planned" (won't fix / false positive), create workflow request
	if event.Action == "closed" && event.Issue.StateReason == "not_planned" && h.workflow != nil {
		req := domain.RiskAcceptanceRequest{
			FindingIDs:    []uuid.UUID{findingID},
			Justification: fmt.Sprintf("External GitHub issue #%d closed as not_planned by %s", event.Issue.Number, event.Sender.Login),
			ExpiresAt:     time.Now().UTC().AddDate(0, 3, 0),
		}
		requester := fmt.Sprintf("connector:%s", conn.Name)
		outcome, err := h.workflow.Request(r.Context(), tenantID, requester, req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to submit risk acceptance request: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":            "request_created",
			"issue_number":      event.Issue.Number,
			"acceptance_status": outcome.Acceptance.Status,
			"acceptance_id":     outcome.Acceptance.ID,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleGenericWebhook handles generic inbound webhooks with HMAC-SHA256 signature verification.
func (h *InboundWebhookHandler) handleGenericWebhook(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, conn *domain.Connector, body []byte) {
	sigHeader := r.Header.Get("X-Hub-Signature-256")
	if sigHeader == "" {
		sigHeader = r.Header.Get("X-Signature")
	}

	var secretBytes []byte
	if conn.Spec.Webhook != nil && conn.Spec.Webhook.SecretRef.Name != "" && h.secretResolver != nil {
		secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Webhook.SecretRef.Key)
		secretBytes, _ = h.secretResolver.GetSecretMaterial(r.Context(), tenantID, secKey)
	}

	if len(secretBytes) > 0 {
		if sigHeader == "" || !VerifyGitHubSignature(secretBytes, body, sigHeader) {
			http.Error(w, "invalid or missing webhook signature", http.StatusUnauthorized)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// VerifyJiraSignature verifies Jira Cloud webhook signatures.
func VerifyJiraSignature(secret, body []byte, sigHeader string) bool {
	cleanSig := strings.TrimSpace(sigHeader)
	cleanSig = strings.TrimPrefix(cleanSig, "sha256=")
	cleanSig = strings.TrimPrefix(cleanSig, "sha1=")

	// Try sha256 first
	mac256 := hmac.New(sha256.New, secret)
	mac256.Write(body)
	expected256 := hex.EncodeToString(mac256.Sum(nil))
	if hmac.Equal([]byte(cleanSig), []byte(expected256)) {
		return true
	}

	// Try sha1
	mac1 := hmac.New(sha1.New, secret)
	mac1.Write(body)
	expected1 := hex.EncodeToString(mac1.Sum(nil))
	return hmac.Equal([]byte(cleanSig), []byte(expected1))
}

// VerifyGitHubSignature verifies GitHub X-Hub-Signature-256 HMAC-SHA256 signatures (D69).
func VerifyGitHubSignature(secret, body []byte, sigHeader string) bool {
	cleanSig := strings.TrimSpace(sigHeader)
	if !strings.HasPrefix(cleanSig, "sha256=") {
		return false
	}
	cleanSig = strings.TrimPrefix(cleanSig, "sha256=")

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(cleanSig), []byte(expected))
}

func extractFindingIDFromLabels(labels []string) uuid.UUID {
	const prefix = "rampart-finding-"
	for _, l := range labels {
		if strings.HasPrefix(l, prefix) {
			idStr := strings.TrimPrefix(l, prefix)
			if id, err := uuid.Parse(idStr); err == nil {
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
			// Search for connectors/{name}
			for j := i + 2; j < len(parts); j++ {
				if parts[j] == "connectors" && j+1 < len(parts) {
					return tID, parts[j+1], nil
				}
			}
		}
	}
	return uuid.Nil, "", errors.New("invalid path: expected /api/v1/t/{tenant}/connectors/{name}/webhook")
}
