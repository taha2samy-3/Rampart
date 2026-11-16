package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/domain"
	"rampart/internal/store"
)

// D78: an inbound webhook names a connector by id alone. As the application role, the lookup finds exactly that
// row and its tenant; an unknown id finds nothing; and the setting it uses does not outlive the lookup, so tenant
// isolation of every other read is unchanged.
func TestGetConnectorByID_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)

	suffix := uuid.New().String()[:8]
	tenantA := &domain.Tenant{ID: uuid.New(), Slug: "hook-a-" + suffix, DisplayName: "A", CreatedAt: time.Now().UTC()}
	tenantB := &domain.Tenant{ID: uuid.New(), Slug: "hook-b-" + suffix, DisplayName: "B", CreatedAt: time.Now().UTC()}
	for _, tn := range []*domain.Tenant{tenantA, tenantB} {
		if err := sysStore.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	conn := domain.Connector{ID: domain.NewID(), Name: "jira-two-way", Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeJira, Direction: domain.DirectionBidirectional,
		Jira: &domain.JiraConnectorConfig{URL: "https://acme.atlassian.net", DefaultProject: "SEC", TwoWaySync: true},
	}}
	if err := sysStore.SaveConnector(ctx, tenantA.ID, conn); err != nil {
		t.Fatal(err)
	}

	got, err := appStore.GetConnectorByID(ctx, conn.ID)
	if err != nil || got == nil {
		t.Fatalf("the application role must find the connector by id: %v", err)
	}
	if got.TenantID != tenantA.ID || got.Name != "jira-two-way" || got.Type != domain.ConnectorTypeJira {
		t.Fatalf("wrong row: %+v", got)
	}

	if _, err := appStore.GetConnectorByID(ctx, uuid.New()); !errors.Is(err, store.ErrConnectorNotFound) {
		t.Fatalf("an unknown id must find nothing, got %v", err)
	}

	// The lookup setting is local to its transaction: afterwards tenant B still sees none of A's connectors.
	for i := 0; i < 3; i++ {
		list, err := appStore.ListConnectors(ctx, tenantB.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Fatalf("SECURITY VIOLATION: tenant B sees %d connectors of tenant A after a webhook lookup", len(list))
		}
		if _, err := appStore.GetConnector(ctx, tenantB.ID, "jira-two-way"); err == nil {
			t.Fatalf("SECURITY VIOLATION: tenant B reads tenant A's connector by name (pass %d)", i)
		}
	}
}
