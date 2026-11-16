package query

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"rampart/internal/domain"
)

// Connectors are configuration resources (D82): they are created by kubectl, GitOps or `rampart apply -f`, never
// through this API. These handlers read connectors, describe the types, and validate a resource before the user
// applies it. Nothing here writes a connector or receives a secret value. A dry run always answers 200 with
// {valid, reason, error}: the request succeeded, the resource is what was judged.

// SetSSRFAllowlist sets the platform allowlist the dry-run validation applies, scoped to the caller's tenant (D77).
func (a *API) SetSSRFAllowlist(al *domain.PlatformSSRFAllowlist) { a.ssrfAllowlist = al }

// ConnectorItem is a connector as the UI lists it: its configuration (secret references only) and the status the
// operator wrote after its Check (D69).
type ConnectorItem struct {
	Name       string                    `json:"name"`
	Type       domain.ConnectorType      `json:"type"`
	Direction  domain.ConnectorDirection `json:"direction"`
	Enabled    bool                      `json:"enabled"`
	ManagedBy  string                    `json:"managed_by"`
	Spec       domain.ConnectorSpec      `json:"spec"`
	Status     connectorItemStatus       `json:"status"`
	WebhookURL string                    `json:"webhook_url,omitempty"`
}

type connectorItemStatus struct {
	Conditions    []connectorItemCondition `json:"conditions"`
	LastCheckTime *time.Time               `json:"last_check_time,omitempty"`
	AccountID     string                   `json:"account_id,omitempty"`
}

type connectorItemCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"last_transition_time"`
}

// handleListConnectors handles GET /api/v1/connectors.
func (a *API) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	conns, err := a.store.ListConnectors(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list connectors")
		return
	}
	items := make([]ConnectorItem, 0, len(conns))
	for _, c := range conns {
		it := ConnectorItem{
			Name: c.Name, Type: c.Type, Direction: c.Direction(), Enabled: true, ManagedBy: "resource",
			Spec: c.Spec, WebhookURL: c.Status.WebhookURL,
			Status: connectorItemStatus{Conditions: []connectorItemCondition{}, LastCheckTime: c.Status.LastSync, AccountID: c.Status.AccountID},
		}
		for _, cond := range c.Status.Conditions {
			it.Status.Conditions = append(it.Status.Conditions, connectorItemCondition(cond))
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleConnectorCatalogue handles GET /api/v1/connectors/catalogue: the types this build supports, with the
// schema generated from the Go config structs and an example the server accepts (D82).
func (a *API) handleConnectorCatalogue(w http.ResponseWriter, r *http.Request) {
	if _, err := a.resolveTenant(r); err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": domain.ConnectorCatalogue()})
}

// ValidateConnectorResult is the answer of the dry run.
type ValidateConnectorResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"` // InvalidSpec | NotSupported | UnsafeAddress, as the operator would set
	Error  string `json:"error,omitempty"`
}

// handleValidateConnector handles POST /api/v1/connectors/validate: the body is a Connector resource in YAML or
// JSON. It runs the validation the operator runs, with the SSRF allowlist scoped to the caller's tenant and the
// connector's type (D77), and stores nothing. A Secret in the body is refused: secret values never come here.
func (a *API) handleValidateConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "The resource is larger than 64 KiB")
		return
	}
	// The UI's client sends JSON, {"resource": "<yaml>"}; kubectl-style callers send the YAML itself.
	var wrapped struct {
		Resource *string `json:"resource"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && wrapped.Resource != nil {
		raw = []byte(*wrapped.Resource)
	}
	doc := strings.SplitN(string(raw), "\n---\n", 2)[0] // the Connector; a Secret template after it is ignored
	jsonDoc, err := yaml.YAMLToJSON([]byte(doc))
	if err != nil {
		writeJSON(w, http.StatusOK, ValidateConnectorResult{Reason: "InvalidSpec", Error: "not YAML or JSON: " + err.Error()})
		return
	}
	var res struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec domain.ConnectorSpec `json:"spec"`
	}
	if err := json.Unmarshal(jsonDoc, &res); err != nil {
		writeJSON(w, http.StatusOK, ValidateConnectorResult{Reason: "InvalidSpec", Error: err.Error()})
		return
	}
	if res.Kind != "Connector" {
		writeJSON(w, http.StatusOK, ValidateConnectorResult{Reason: "InvalidSpec",
			Error: "the first document must be a Connector; send the Secret with kubectl, never here"})
		return
	}
	conn := domain.Connector{TenantID: tenantID, Name: res.Metadata.Name, Type: res.Spec.Type, Spec: res.Spec}
	if err := conn.ValidateWithAllowlist(a.ssrfAllowlist.ScopedTo(tenantID, conn.Type)); err != nil {
		writeJSON(w, http.StatusOK, ValidateConnectorResult{Reason: connectorReason(err), Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ValidateConnectorResult{Valid: true})
}

// connectorReason maps a validation error to the reason the operator writes in the Ready condition.
func connectorReason(err error) string {
	switch {
	case errors.Is(err, domain.ErrConnectorNotSupported):
		return "NotSupported"
	case errors.Is(err, domain.ErrSSRFBlocked):
		return "UnsafeAddress"
	default:
		return "InvalidSpec"
	}
}
