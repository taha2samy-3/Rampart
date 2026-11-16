package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

type queued struct {
	tenant    uuid.UUID
	connector string
	msg       []byte
}

type fakeDeliveryQueue struct {
	mu   sync.Mutex
	jobs []queued
}

func (q *fakeDeliveryQueue) EnqueueDelivery(_ context.Context, tenantID uuid.UUID, connector string, message []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jobs = append(q.jobs, queued{tenantID, connector, message})
	return nil
}

// TestDeliveryQueue covers docs/23 K4: with a queue, routing sends nothing itself; it queues one job per connector
// and message, the routing rules still apply, a tracker is never queued, and Deliver sends the queued message.
func TestDeliveryQueue(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()

	var mu sync.Mutex
	var received [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hook := func(name string, routing *domain.NotificationRoutingRule) domain.Connector {
		return domain.Connector{Name: name, Type: domain.ConnectorTypeWebhook, Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeWebhook, Webhook: &domain.WebhookConnectorConfig{URL: srv.URL, Format: "raw"}, Routing: routing,
		}}
	}
	_ = st.SaveConnector(ctx, tenantID, hook("all", nil))
	_ = st.SaveConnector(ctx, tenantID, hook("critical-only", &domain.NotificationRoutingRule{MinSeverity: "critical"}))
	_ = st.SaveConnector(ctx, tenantID, domain.Connector{Name: "jira", Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeJira, Jira: &domain.JiraConnectorConfig{URL: "https://jira.example.com", DefaultProject: "SEC"},
	}})

	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	router := connectors.NewNotificationRouterWithConfig(st, nil, client, connectors.RouterConfig{PublicURL: "https://rampart.example.com"})
	q := &fakeDeliveryQueue{}
	router.SetDeliveryQueue(q)

	high := connectors.NewNotificationMessage(tenantID.String(), "shop", "A high finding", "s", "high", "https://rampart.example.com/x", "f1")
	if errs := router.RouteNotification(ctx, tenantID, high); len(errs) != 0 {
		t.Fatalf("route: %v", errs)
	}
	if len(q.jobs) != 1 || q.jobs[0].connector != "all" || q.jobs[0].tenant != tenantID {
		t.Fatalf("a high message is queued once, for the connector without a severity floor; got %+v", q.jobs)
	}
	mu.Lock()
	if len(received) != 0 {
		t.Fatalf("routing with a queue must not send; the receiver got %d requests", len(received))
	}
	mu.Unlock()

	crit := connectors.NewNotificationMessage(tenantID.String(), "shop", "A critical finding", "s", "critical", "https://rampart.example.com/y", "f2")
	_ = router.RouteNotification(ctx, tenantID, crit)
	if len(q.jobs) != 3 {
		t.Fatalf("a critical message goes to both webhooks and never to the tracker; got %d jobs", len(q.jobs))
	}

	// The ingest path queues the same way, one job per finding and connector.
	q.jobs = nil
	findings := []*domain.Finding{{ID: uuid.New(), Title: "f", Severity: domain.SeverityCritical}}
	if errs := router.RouteIngestRunFindings(ctx, tenantID, "shop", findings); len(errs) != 0 {
		t.Fatalf("route run: %v", errs)
	}
	if len(q.jobs) != 2 {
		t.Fatalf("one critical finding, two webhooks: want 2 jobs, got %d", len(q.jobs))
	}

	// The worker's side: the queued message is sent as it was routed.
	var msg connectors.NotificationMessage
	if err := json.Unmarshal(q.jobs[0].msg, &msg); err != nil {
		t.Fatal(err)
	}
	if err := router.Deliver(ctx, tenantID, q.jobs[0].connector, msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	mu.Lock()
	if len(received) != 1 {
		t.Fatalf("Deliver sends once; the receiver got %d requests", len(received))
	}
	mu.Unlock()

	// A connector deleted after the message was queued is not retried.
	if err := router.Deliver(ctx, tenantID, "deleted-since", msg); !errors.Is(err, connectors.ErrConnectorGone) {
		t.Fatalf("want ErrConnectorGone, got %v", err)
	}

	// A receiver that fails gives an error, so the queue retries.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if err := router.Deliver(ctx, tenantID, "all", msg); err == nil {
		t.Fatal("a 502 must be returned for a retry")
	}
}
