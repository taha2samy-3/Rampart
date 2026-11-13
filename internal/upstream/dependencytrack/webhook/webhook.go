// Package webhook provides the HTTP receiver for Dependency-Track notification events (docs/10 §2 Flow B, docs/21 §4.3).
package webhook

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/store"
)

const MaxWebhookBodyBytes = 512 * 1024 // 512 KiB

// SecretResolver resolves stored credentials.
type SecretResolver interface {
	GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error)
}

// ProjectSyncer triggers a project sync pass.
type ProjectSyncer interface {
	SyncProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) error
}

// Handler handles incoming Dependency-Track webhook notifications.
type Handler struct {
	store   store.DTrackStore
	secrets SecretResolver
	syncer  ProjectSyncer
	logger  *slog.Logger
}

// NewHandler creates a new Dependency-Track webhook Handler.
func NewHandler(dtrackStore store.DTrackStore, secrets SecretResolver, syncer ProjectSyncer) *Handler {
	return &Handler{
		store:   dtrackStore,
		secrets: secrets,
		syncer:  syncer,
		logger:  slog.Default().With("component", "dtrack_webhook"),
	}
}

type dtNotificationPayload struct {
	Notification struct {
		Level     string `json:"level"`
		Scope     string `json:"scope"`
		Group     string `json:"group"`
		Timestamp string `json:"timestamp"`
		Title     string `json:"title,omitempty"`
		Content   string `json:"content,omitempty"`
		Subject   struct {
			Project struct {
				UUID string `json:"uuid"`
				Name string `json:"name,omitempty"`
			} `json:"project"`
			AffectedProjects []struct {
				UUID string `json:"uuid"`
				Name string `json:"name,omitempty"`
			} `json:"affectedProjects"`
		} `json:"subject"`
	} `json:"notification"`
	// Some versions/templates post subject at root
	Subject struct {
		Project struct {
			UUID string `json:"uuid"`
			Name string `json:"name,omitempty"`
		} `json:"project"`
	} `json:"subject"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Extract source ID from path: /hooks/dependency-track/{id}
	idStr := r.PathValue("id")
	if idStr == "" {
		// Fallback for paths without PathValue router
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "hooks" && parts[1] == "dependency-track" {
			idStr = parts[2]
		}
	}

	sourceID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid source id in path", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 2. Lookup scan source to determine tenant
	tenantID, sourceName, err := h.store.LookupScanSource(ctx, sourceID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "source not found", http.StatusNotFound)
		return
	}
	if err != nil {
		h.logger.Error("failed looking up scan source", "source_id", sourceID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Authenticate Bearer secret in constant time (docs/21 §4.3)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.logger.Warn("missing authorization header", "source_id", sourceID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token := strings.TrimSpace(authHeader)
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	} else if strings.HasPrefix(token, "Token ") {
		token = strings.TrimPrefix(token, "Token ")
	}
	token = strings.TrimSpace(token)

	expectedSecret, secErr := h.secrets.GetSecretMaterial(ctx, tenantID, "scansource:"+sourceName+":webhook")
	if secErr != nil || len(expectedSecret) == 0 {
		// Fallback to scansource:<id>:webhook
		expectedSecret, secErr = h.secrets.GetSecretMaterial(ctx, tenantID, "scansource:"+sourceID.String()+":webhook")
	}

	if secErr != nil || len(expectedSecret) == 0 || subtle.ConstantTimeCompare([]byte(token), expectedSecret) != 1 {
		h.logger.Warn("invalid webhook secret", "source_id", sourceID, "tenant_id", tenantID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 4. Read body bounded to MaxWebhookBodyBytes
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxWebhookBodyBytes))
	if err != nil {
		http.Error(w, "failed reading body", http.StatusBadRequest)
		return
	}

	var payload dtNotificationPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.logger.Warn("malformed webhook payload", "source_id", sourceID, "error", err)
		http.Error(w, "malformed json payload", http.StatusBadRequest)
		return
	}

	// 5. Thin event, fat fetch: collect project UUIDs only (docs/10 §2)
	projectUUIDs := make(map[string]bool)
	if pUUID := strings.TrimSpace(payload.Notification.Subject.Project.UUID); pUUID != "" {
		projectUUIDs[pUUID] = true
	}
	for _, ap := range payload.Notification.Subject.AffectedProjects {
		if pUUID := strings.TrimSpace(ap.UUID); pUUID != "" {
			projectUUIDs[pUUID] = true
		}
	}
	if pUUID := strings.TrimSpace(payload.Subject.Project.UUID); pUUID != "" {
		projectUUIDs[pUUID] = true
	}

	group := payload.Notification.Group
	if group == "BOM_PROCESSING_FAILED" || group == "BOM_VALIDATION_FAILED" {
		h.logger.Warn("dependency-track reported processing failure", "group", group, "source_id", sourceID)
	}

	// 6. Enqueue project sync with trailing-edge debounce
	for pUUID := range projectUUIDs {
		shouldStart, err := h.store.EnqueueDTrackSync(ctx, tenantID, sourceID, pUUID)
		if err != nil {
			h.logger.Error("failed enqueuing dtrack sync", "project", pUUID, "error", err)
			continue
		}
		if shouldStart && h.syncer != nil {
			go func(proj string) {
				_ = h.syncer.SyncProject(context.Background(), tenantID, sourceID, proj)
			}(pUUID)
		}
	}

	// 7. Acknowledge with 202 Accepted
	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}
