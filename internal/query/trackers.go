package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"rampart/internal/auth"
	"rampart/internal/domain"
	trackerclient "rampart/internal/tracker/client"
)

const trackerTestTimeout = 10 * time.Second

// TrackerProbe dials an external tracker container and asks for its health and metadata (never sends secrets).
type TrackerProbe func(ctx context.Context, cfg trackerclient.DialConfig) (trackerclient.ProbeResult, error)

// SetTrackerProbe replaces the dial+probe call used by POST /api/v1/trackers/test (tests).
func (a *API) SetTrackerProbe(p TrackerProbe) { a.trackerProbe = p }

type trackerItem struct {
	Scope          string            `json:"scope"`
	Namespace      string            `json:"namespace,omitempty"`
	Name           string            `json:"name"`
	Enabled        bool              `json:"enabled"`
	State          string            `json:"state"` // ready | disabled | refused
	Reason         string            `json:"reason,omitempty"`
	Protocol       string            `json:"protocol"`
	Target         string            `json:"target,omitempty"`
	TLS            string            `json:"tls"` // off | tls
	TimeoutSeconds int               `json:"timeout_seconds"`
	BoundCount     int               `json:"bound_connectors"`
	Last           *trackerEventItem `json:"last_event,omitempty"`
	UpdatedAt      *time.Time        `json:"updated_at,omitempty"`
}

type trackerEventItem struct {
	ID        string            `json:"id"`
	Event     string            `json:"event"`
	Outcome   string            `json:"outcome"`
	Message   string            `json:"message"`
	Detail    map[string]string `json:"detail,omitempty"`
	LatencyMs int64             `json:"latency_ms"`
	Actor     string            `json:"actor,omitempty"`
	At        time.Time         `json:"at"`
}

type trackerEventStore interface {
	domain.TrackerEvents
}

func trackerEventItemOf(e domain.TrackerEvent) trackerEventItem {
	return trackerEventItem{
		ID:        e.ID.String(),
		Event:     e.Event,
		Outcome:   e.Outcome,
		Message:   e.Message,
		Detail:    e.Detail,
		LatencyMs: e.Duration.Milliseconds(),
		Actor:     e.Actor,
		At:        e.CreatedAt,
	}
}

func trackerItemOf(o domain.StoredTrackerObject, boundCount int) trackerItem {
	it := trackerItem{
		Scope:          o.Origin,
		Namespace:      o.Namespace,
		Name:           o.Name,
		Protocol:       "grpc",
		TimeoutSeconds: int(domain.DefaultTrackerTimeout.Seconds()),
		TLS:            "off",
		BoundCount:     boundCount,
	}
	if !o.UpdatedAt.IsZero() {
		t := o.UpdatedAt
		it.UpdatedAt = &t
	}
	if o.Error != "" {
		it.State, it.Reason = "refused", o.Error
		if s, err := domain.ParseExternalTrackerSpec(o.Spec, o.Origin == "tenant"); err == nil {
			it.Enabled = s.IsEnabled()
			it.Target = s.Target(o.Namespace)
			it.TimeoutSeconds = int(s.Timeout().Seconds())
		}
		return it
	}
	spec, err := domain.ParseExternalTrackerSpec(o.Spec, o.Origin == "tenant")
	if err != nil {
		it.State, it.Reason = "refused", err.Error()
		return it
	}
	it.Enabled = spec.IsEnabled()
	if spec.Protocol != "" {
		it.Protocol = spec.Protocol
	}
	it.Target = spec.Target(o.Namespace)
	if spec.UseTLS() {
		it.TLS = "tls"
	}
	it.TimeoutSeconds = int(spec.Timeout().Seconds())
	it.State = "disabled"
	if spec.IsEnabled() {
		it.State = "ready"
	}
	return it
}

// handleListTrackers handles GET /api/v1/trackers: cluster and tenant external tracker containers visible to the caller's tenant.
func (a *API) handleListTrackers(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	st, ok := a.store.(domain.TrackerStore)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"items": []trackerItem{}, "total": 0})
		return
	}
	list, err := st.ListTrackers(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Could not list external trackers")
		return
	}

	// Count how many tenant connectors bind to each tracker container.
	boundCounts := map[string]int{}
	if conns, err := a.store.ListConnectors(r.Context(), tenantID); err == nil {
		for _, c := range conns {
			if c.Type != domain.ConnectorTypeExternalTracker || c.Spec.ExternalTracker == nil {
				continue
			}
			ref := c.Spec.ExternalTracker.TrackerRef
			sc := strings.ToLower(strings.TrimSpace(ref.Scope))
			if sc == "" {
				sc = "cluster"
			}
			ns := ref.Namespace
			if sc == "cluster" {
				ns = ""
			}
			boundCounts[sc+"|"+ns+"|"+ref.Name]++
		}
	}

	ev, hasEv := a.store.(trackerEventStore)
	items := make([]trackerItem, 0, len(list))
	for _, o := range list {
		ns := o.Namespace
		if o.Origin == "cluster" {
			ns = ""
		}
		it := trackerItemOf(o, boundCounts[o.Origin+"|"+ns+"|"+o.Name])
		if hasEv {
			if last, err := ev.ListTrackerEvents(r.Context(), tenantID, it.Scope, it.Namespace, it.Name, 1); err == nil && len(last) > 0 {
				e := trackerEventItemOf(last[0])
				it.Last = &e
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// handleTrackerEvents handles GET /api/v1/trackers/events for one tracker container.
func (a *API) handleTrackerEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	q := r.URL.Query()
	scope, name := q.Get("scope"), strings.TrimSpace(q.Get("name"))
	if (scope != "cluster" && scope != "tenant") || name == "" {
		problem(w, http.StatusBadRequest, "invalid-request", "scope (cluster or tenant) and name are required")
		return
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &limit); err != nil || limit < 1 || limit > 200 {
			problem(w, http.StatusBadRequest, "invalid-request", "limit is a number from 1 to 200")
			return
		}
	}
	out := []trackerEventItem{}
	if ev, ok := a.store.(domain.TrackerEvents); ok {
		list, err := ev.ListTrackerEvents(r.Context(), tenantID, scope, q.Get("namespace"), name, limit)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Could not list tracker events")
			return
		}
		for _, e := range list {
			out = append(out, trackerEventItemOf(e))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "total": len(out)})
}

type trackerTestRequest struct {
	Scope     string `json:"scope"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type trackerDeclaredSecret struct {
	Name     string `json:"name"`
	Holds    string `json:"holds,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
	Required bool   `json:"required"`
}

type trackerTestResult struct {
	OK              bool                    `json:"ok"`
	Outcome         string                  `json:"outcome"`
	Message         string                  `json:"message"`
	LatencyMs       int64                   `json:"latency_ms"`
	Provider        string                  `json:"provider,omitempty"`
	DisplayName     string                  `json:"display_name,omitempty"`
	Version         string                  `json:"version,omitempty"`
	Capabilities    []string                `json:"capabilities,omitempty"`
	ConfigSchema    json.RawMessage         `json:"config_schema,omitempty"`
	DeclaredSecrets []trackerDeclaredSecret `json:"declared_secrets,omitempty"`
	ExampleYAML     string                  `json:"example_yaml,omitempty"`
	Detail          map[string]string       `json:"detail,omitempty"`
	Event           *trackerEventItem       `json:"event,omitempty"`
}

// handleTestTracker handles POST /api/v1/trackers/test (Admin): probes HealthCheck + GetMetadata without secrets.
func (a *API) handleTestTracker(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	var req trackerTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "The body must be JSON with scope, namespace and name")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if (req.Scope != "cluster" && req.Scope != "tenant") || req.Name == "" {
		problem(w, http.StatusBadRequest, "invalid-request", "scope (cluster or tenant) and name are required")
		return
	}
	st, ok := a.store.(domain.TrackerStore)
	if !ok {
		problem(w, http.StatusNotImplemented, "not-implemented", "This server does not store external trackers")
		return
	}
	ns := req.Namespace
	if req.Scope == "cluster" {
		ns = ""
	}
	obj, found, err := st.GetTracker(r.Context(), tenantID, req.Scope, ns, req.Name)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Could not read tracker definition")
		return
	}
	if !found {
		problem(w, http.StatusNotFound, "not-found", "No such external tracker")
		return
	}

	started := time.Now()
	res := trackerTestResult{Detail: map[string]string{}}
	a.testExternalTracker(r.Context(), obj, &res)
	elapsed := time.Since(started)
	res.LatencyMs = elapsed.Milliseconds()
	res.Outcome = "failed"
	if res.OK {
		res.Outcome = "succeeded"
	}
	if ev, ok := a.store.(domain.TrackerEvents); ok {
		e := domain.TrackerEvent{
			ID:        domain.NewID(),
			Scope:     req.Scope,
			Namespace: ns,
			Name:      req.Name,
			Event:     "test",
			Outcome:   res.Outcome,
			Message:   res.Message,
			Detail:    res.Detail,
			Duration:  elapsed,
			Actor:     actorOf(user),
			CreatedAt: time.Now().UTC(),
		}
		if err := ev.RecordTrackerEvent(r.Context(), tenantID, e); err == nil {
			item := trackerEventItemOf(e)
			res.Event = &item
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *API) testExternalTracker(ctx context.Context, o domain.StoredTrackerObject, res *trackerTestResult) {
	spec, err := domain.ParseExternalTrackerSpec(o.Spec, o.Origin == "tenant")
	if err != nil {
		res.Message = "The tracker spec was refused, so there is nothing to dial: " + err.Error()
		return
	}
	target := spec.Target(o.Namespace)
	res.Detail["target"] = target
	res.Detail["enabled"] = fmt.Sprint(spec.IsEnabled())
	res.Detail["secure"] = fmt.Sprint(spec.UseTLS())
	timeout := spec.Timeout()
	if timeout > trackerTestTimeout {
		timeout = trackerTestTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	probe := a.trackerProbe
	if probe == nil {
		probe = trackerclient.Probe
	}
	pr, err := probe(cctx, trackerclient.DialConfig{
		Target:  target,
		Secure:  spec.UseTLS(),
		Timeout: timeout,
	})
	if pr.Latency > 0 {
		res.Detail["answered_in_ms"] = fmt.Sprint(pr.Latency.Milliseconds())
	}
	switch {
	case err != nil:
		res.Message = "Could not reach " + target + ": " + describeTrackerProbeError(err, timeout)
	case !pr.Serving:
		res.Detail["tracker_says"] = pr.Message
		res.Message = "Tracker container answered but is not serving: " + firstNonEmpty(pr.Message, "no reason given")
	default:
		res.OK = true
		res.Provider = pr.Provider
		res.DisplayName = pr.DisplayName
		res.Version = pr.Version
		res.Capabilities = pr.Capabilities
		res.ExampleYAML = pr.ExampleYAML
		if pr.ConfigSchemaJSON != "" && json.Valid([]byte(pr.ConfigSchemaJSON)) {
			res.ConfigSchema = json.RawMessage(pr.ConfigSchemaJSON)
		}
		for _, ds := range pr.DeclaredSecrets {
			res.DeclaredSecrets = append(res.DeclaredSecrets, trackerDeclaredSecret{
				Name:     ds.GetName(),
				Holds:    ds.GetHolds(),
				Purpose:  ds.GetPurpose(),
				Required: ds.GetRequired(),
			})
		}
		res.Detail["provider"] = pr.Provider
		res.Detail["name"] = pr.DisplayName
		res.Detail["version"] = pr.Version
		res.Detail["capabilities"] = strings.Join(pr.Capabilities, ",")
		res.Detail["tracker_says"] = pr.Message
		res.Message = fmt.Sprintf("Serving: %s %s (%s)", firstNonEmpty(pr.DisplayName, firstNonEmpty(pr.Provider, "tracker container")), pr.Version, strings.Join(pr.Capabilities, ", "))
		if !spec.IsEnabled() {
			res.Message += " (the resource is disabled, so it is not used)"
		}
	}
}

func describeTrackerProbeError(err error, timeout time.Duration) string {
	switch status.Code(err) {
	case codes.DeadlineExceeded:
		return fmt.Sprintf("no answer within %s", timeout)
	case codes.Unavailable:
		return "nothing answers there (the Service or pod is down, the port is wrong, or TLS does not match): " + status.Convert(err).Message()
	case codes.Unimplemented:
		return "it does not implement TrackerService"
	case codes.Unauthenticated, codes.PermissionDenied:
		return "it refused the call: " + status.Convert(err).Message()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("no answer within %s", timeout)
	}
	return err.Error()
}

// handleListTickets handles GET /api/v1/tickets: returns opened tickets and pending/failed outbox entries.
func (a *API) handleListTickets(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &limit); err != nil || limit < 1 || limit > 200 {
			problem(w, http.StatusBadRequest, "invalid-request", "limit must be between 1 and 200")
			return
		}
	}
	qr, ok := a.store.(domain.TicketQueueReader)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"tickets":    []domain.TicketSummary{},
			"outbox":     []domain.TicketOutboxItem{},
			"configured": false,
		})
		return
	}
	tickets, err := qr.ListTickets(r.Context(), tenantID, limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Could not list tickets")
		return
	}
	outbox, err := qr.ListTicketOutbox(r.Context(), tenantID, limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Could not list ticket outbox")
		return
	}
	if tickets == nil {
		tickets = []domain.TicketSummary{}
	}
	if outbox == nil {
		outbox = []domain.TicketOutboxItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tickets":    tickets,
		"outbox":     outbox,
		"configured": true,
	})
}
