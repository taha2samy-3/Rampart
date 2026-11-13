package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func TestMemoryStore_Connectors(t *testing.T) {
	ctx := context.Background()
	m := ingest.NewMemoryStore()

	tenantID := uuid.New()
	conn := domain.Connector{
		Name: "slack-notifications",
		Type: domain.ConnectorTypeSlack,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeSlack,
			Slack: &domain.SlackConnectorConfig{
				TokenSecretRef: domain.SecretKeyRef{Name: "slack-sec", Key: "token"},
				DefaultChannel: "#sec-alerts",
			},
		},
	}

	// 1. Save
	if err := m.SaveConnector(ctx, tenantID, conn); err != nil {
		t.Fatalf("SaveConnector failed: %v", err)
	}

	// 2. Get
	fetched, err := m.GetConnector(ctx, tenantID, "slack-notifications")
	if err != nil {
		t.Fatalf("GetConnector failed: %v", err)
	}
	if fetched.Name != "slack-notifications" || fetched.Type != domain.ConnectorTypeSlack {
		t.Errorf("unexpected fetched connector: %+v", fetched)
	}

	// 3. List
	list, err := m.ListConnectors(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListConnectors failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(list))
	}

	// 4. Update status
	now := time.Now().UTC()
	status := domain.ConnectorStatus{
		ObservedGeneration: 1,
		LastSync:           &now,
		Conditions: []domain.ConnectorCondition{
			{
				Type:               "Connected",
				Status:             "True",
				Reason:             "AuthOK",
				Message:            "Verified bot token",
				LastTransitionTime: now,
			},
		},
	}
	if err := m.UpdateConnectorStatus(ctx, tenantID, "slack-notifications", status); err != nil {
		t.Fatalf("UpdateConnectorStatus failed: %v", err)
	}

	fetchedAfterStatus, err := m.GetConnector(ctx, tenantID, "slack-notifications")
	if err != nil {
		t.Fatalf("GetConnector after status failed: %v", err)
	}
	if !fetchedAfterStatus.IsConnected() {
		t.Errorf("expected IsConnected to be true")
	}

	// 5. Delete
	if err := m.DeleteConnector(ctx, tenantID, "slack-notifications"); err != nil {
		t.Fatalf("DeleteConnector failed: %v", err)
	}

	_, err = m.GetConnector(ctx, tenantID, "slack-notifications")
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}
