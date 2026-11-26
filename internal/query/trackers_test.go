package query_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
	trackerclient "rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

type queryStoreWithTrackers struct {
	*ingest.MemoryStore
	trackers *apply.MemoryConfigStore
	tickets  []domain.TicketSummary
	outbox   []domain.TicketOutboxItem
}

func (s *queryStoreWithTrackers) ListTrackers(ctx context.Context, tenantID uuid.UUID) ([]domain.StoredTrackerObject, error) {
	return s.trackers.ListTrackers(ctx, tenantID)
}

func (s *queryStoreWithTrackers) GetTracker(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string) (domain.StoredTrackerObject, bool, error) {
	return s.trackers.GetTracker(ctx, tenantID, scope, namespace, name)
}

func (s *queryStoreWithTrackers) RecordTrackerEvent(ctx context.Context, tenantID uuid.UUID, ev domain.TrackerEvent) error {
	return s.trackers.RecordTrackerEvent(ctx, tenantID, ev)
}

func (s *queryStoreWithTrackers) ListTrackerEvents(ctx context.Context, tenantID uuid.UUID, scope, namespace, name string, limit int) ([]domain.TrackerEvent, error) {
	return s.trackers.ListTrackerEvents(ctx, tenantID, scope, namespace, name, limit)
}

func (s *queryStoreWithTrackers) ListTickets(_ context.Context, _ uuid.UUID, _ int) ([]domain.TicketSummary, error) {
	return s.tickets, nil
}

func (s *queryStoreWithTrackers) ListTicketOutbox(_ context.Context, _ uuid.UUID, _ int) ([]domain.TicketOutboxItem, error) {
	return s.outbox, nil
}

func TestTrackersAPI_ListTestEventsAndTickets(t *testing.T) {
	ctx := context.Background()
	mem := ingest.NewMemoryStore()
	cfgStore := apply.NewMemoryConfigStore()
	tenantID := domain.NewID()
	_ = cfgStore.SaveClusterPolicy(ctx, domain.TrackerKindExternal, apply.PolicyObject{
		Name: "jira-container",
		Spec: []byte(`{"service":{"name":"jira-tracker","namespace":"tools","port":50051}}`),
	})
	_ = mem.SaveConnector(ctx, tenantID, domain.Connector{
		Name: "jira-binding",
		Type: domain.ConnectorTypeExternalTracker,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeExternalTracker,
			ExternalTracker: &domain.ExternalTrackerConnectorConfig{
				TrackerRef:     domain.ExternalTrackerRef{Scope: "cluster", Name: "jira-container"},
				DefaultProject: "SEC",
			},
		},
	})

	wrapped := &queryStoreWithTrackers{
		MemoryStore: mem,
		trackers:    cfgStore,
		tickets: []domain.TicketSummary{{
			ID: domain.NewID(), Connector: "jira-binding", ExternalRef: "SEC-12", State: "open", FindingCount: 1,
		}},
		outbox: []domain.TicketOutboxItem{{
			FindingID: domain.NewID(), FindingTitle: "SQLi", Severity: "critical", Status: "reserved", Attempts: 1,
		}},
	}

	authn := auth.NewAuthenticatorWithStore(wrapped)
	adminTok := auth.FormatToken(tenantID, "admin_tok_trackers")
	viewerTok := auth.FormatToken(tenantID, "viewer_tok_trackers")
	authn.RegisterToken(adminTok, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenantID, Subject: "ada", Role: auth.RoleAdmin, CreatedAt: time.Now().UTC()})
	authn.RegisterToken(viewerTok, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenantID, Subject: "vera", Role: auth.RoleViewer, CreatedAt: time.Now().UTC()})

	api := query.NewAPIWithAuth(wrapped, enrich.NewFeedStore(), authn)
	api.SetTrackerProbe(func(ctx context.Context, cfg trackerclient.DialConfig) (trackerclient.ProbeResult, error) {
		return trackerclient.ProbeResult{
			Serving:          true,
			Message:          "ready",
			Provider:         "jira",
			DisplayName:      "Jira Container",
			Version:          "1.2.0",
			Capabilities:     []string{"create_issue", "two_way_webhook"},
			ConfigSchemaJSON: `{"type":"object","properties":{"defaultProject":{"type":"string"}}}`,
			DeclaredSecrets:  []*trackerv1.SecretDeclaration{{Name: "token", Required: true}},
			ExampleYAML:      "kind: Connector",
			Latency:          5 * time.Millisecond,
		}, nil
	})
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	rig := &analyzerRig{t: t, mux: mux}

	// 1. Viewer lists trackers and sees bound_connectors = 1
	code, body := rig.call(viewerTok, http.MethodGet, "/api/v1/trackers", "")
	if code != http.StatusOK || body["total"].(float64) != 1 {
		t.Fatalf("GET /api/v1/trackers failed: code=%d body=%v", code, body)
	}
	items := body["items"].([]any)
	first := items[0].(map[string]any)
	if first["bound_connectors"].(float64) != 1 || first["state"] != "ready" {
		t.Fatalf("unexpected tracker item: %+v", first)
	}

	// 2. Viewer is forbidden from POST /api/v1/trackers/test
	code, _ = rig.call(viewerTok, http.MethodPost, "/api/v1/trackers/test", `{"scope":"cluster","name":"jira-container"}`)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer test, got %d", code)
	}

	// 3. Admin tests tracker container and persists event
	code, res := rig.call(adminTok, http.MethodPost, "/api/v1/trackers/test", `{"scope":"cluster","name":"jira-container"}`)
	if code != http.StatusOK || res["ok"] != true || res["provider"] != "jira" {
		t.Fatalf("POST /api/v1/trackers/test failed: code=%d body=%v", code, res)
	}

	// 4. Events endpoint lists recorded event
	code, evBody := rig.call(viewerTok, http.MethodGet, "/api/v1/trackers/events?scope=cluster&name=jira-container", "")
	if code != http.StatusOK || evBody["total"].(float64) != 1 {
		t.Fatalf("GET /api/v1/trackers/events failed: code=%d body=%v", code, evBody)
	}

	// 5. Tickets queue endpoint returns tickets + outbox
	code, qBody := rig.call(viewerTok, http.MethodGet, "/api/v1/tickets", "")
	if code != http.StatusOK || qBody["configured"] != true {
		t.Fatalf("GET /api/v1/tickets failed: code=%d body=%v", code, qBody)
	}
	if len(qBody["tickets"].([]any)) != 1 || len(qBody["outbox"].([]any)) != 1 {
		t.Fatalf("unexpected tickets/outbox counts: %v", qBody)
	}
}
