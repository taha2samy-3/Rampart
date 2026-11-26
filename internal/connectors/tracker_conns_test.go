package connectors_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	trackerclient "rampart/internal/tracker/client"
)

// docs/51 step 1.4: the ticket sweeper resolves the tracker once per pending ticket; that must not dial once per ticket.
func TestDefaultTrackerResolver_ReusesOneConnectionPerTracker(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	svc := &fakeTrackerService{}
	st := &storeWithTrackers{
		MemoryStore: ingest.NewMemoryStore(),
		trackers: []domain.StoredTrackerObject{
			{Origin: "cluster", Name: "jira-container", Spec: []byte(`{"service":{"name":"jira-svc","namespace":"tools","port":50051}}`)},
		},
	}
	conn := domain.Connector{
		Name: "jira-ext", TenantID: tenantID, Type: domain.ConnectorTypeExternalTracker,
		Spec: domain.ConnectorSpec{
			Type:            domain.ConnectorTypeExternalTracker,
			ExternalTracker: &domain.ExternalTrackerConnectorConfig{TrackerRef: domain.ExternalTrackerRef{Scope: "cluster", Name: "jira-container"}},
			Ticketing:       &domain.ConnectorTicketingPolicy{OnCritical: true},
		},
	}
	_ = st.SaveConnector(ctx, tenantID, conn)

	var mu sync.Mutex
	var dials []trackerclient.DialConfig
	var clients []*trackerclient.Client
	resolver := connectors.NewDefaultTrackerResolver(st, &mockSecretResolver{}, loopbackClient(), "")
	resolver.SetTrackerDialer(func(cfg trackerclient.DialConfig) (*trackerclient.Client, error) {
		mu.Lock()
		defer mu.Unlock()
		dials = append(dials, cfg)
		c := startFakeTrackerClient(t, svc)
		clients = append(clients, c)
		return c, nil
	})

	for i := 0; i < 25; i++ {
		tr, err := resolver.ResolveTracker(ctx, tenantID)
		if err != nil || tr == nil {
			t.Fatalf("resolve %d: tr=%v err=%v", i, tr, err)
		}
		// A resolved tracker's connection is shared: CloseClient must leave it open for the next ticket.
		if err := tr.(*connectors.GrpcTracker).CloseClient(); err != nil {
			t.Fatalf("CloseClient: %v", err)
		}
	}
	if len(dials) != 1 {
		t.Fatalf("25 resolves dialed %d times, want 1", len(dials))
	}
	if !dials[0].Secure {
		t.Fatalf("a tracker with no tls block must be dialed with TLS: %+v", dials[0])
	}
	tr, _ := resolver.ResolveTracker(ctx, tenantID)
	if _, err := tr.(*connectors.GrpcTracker).CheckDetailed(ctx); err != nil {
		t.Fatalf("the shared connection was closed by CloseClient: %v", err)
	}
	if n := resolver.Connections().Len(); n != 1 {
		t.Fatalf("kept connections = %d, want 1", n)
	}

	// The spec changes: the next resolve dials the new address once and the old connection is closed.
	st.trackers[0].Spec = []byte(`{"service":{"name":"jira-svc-v2","namespace":"tools","port":50051},"tls":{"insecure":true}}`)
	for i := 0; i < 5; i++ {
		if _, err := resolver.ResolveTracker(ctx, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	if len(dials) != 2 || dials[1].Target != "jira-svc-v2.tools.svc.cluster.local:50051" || dials[1].Secure {
		t.Fatalf("after a spec change want one new plaintext dial to v2, got %+v", dials)
	}
	if err := clients[0].Close(); err == nil {
		t.Fatalf("the old connection was not closed when the spec changed")
	}

	// Shutdown closes every connection; nothing dials afterwards.
	if err := resolver.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := clients[1].Close(); err == nil {
		t.Fatalf("Close left a connection open")
	}
	if _, err := resolver.ResolveTracker(ctx, tenantID); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatalf("resolve after Close: err = %v", err)
	}
	if len(dials) != 2 {
		t.Fatalf("dialed after Close: %+v", dials)
	}
}

func TestDefaultTrackerResolver_RefusesTenantTrackerInAnotherNamespace(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	// A row stored before the namespace rule: it must not be dialed.
	st := &storeWithTrackers{
		MemoryStore: ingest.NewMemoryStore(),
		trackers: []domain.StoredTrackerObject{
			{Origin: "tenant", Namespace: "acme", Name: "mine", Spec: []byte(`{"service":{"name":"jira","namespace":"rampart-system","port":50051}}`)},
		},
	}
	_ = st.SaveConnector(ctx, tenantID, domain.Connector{
		Name: "jira-ext", TenantID: tenantID, Type: domain.ConnectorTypeExternalTracker,
		Spec: domain.ConnectorSpec{
			Type:            domain.ConnectorTypeExternalTracker,
			ExternalTracker: &domain.ExternalTrackerConnectorConfig{TrackerRef: domain.ExternalTrackerRef{Scope: "tenant", Namespace: "acme", Name: "mine"}},
			Ticketing:       &domain.ConnectorTicketingPolicy{OnCritical: true},
		},
	})
	resolver := connectors.NewDefaultTrackerResolver(st, &mockSecretResolver{}, loopbackClient(), "")
	resolver.SetTrackerDialer(func(trackerclient.DialConfig) (*trackerclient.Client, error) {
		return nil, errors.New("must not dial")
	})
	if _, err := resolver.ResolveTracker(ctx, tenantID); err == nil || !strings.Contains(err.Error(), "own namespace") {
		t.Fatalf("err = %v, want the namespace refusal", err)
	}
}
