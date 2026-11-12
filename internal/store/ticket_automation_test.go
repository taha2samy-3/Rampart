package store_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func TestReserveActionIdempotency(t *testing.T) {
	url := os.Getenv("RAMPART_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("RAMPART_TEST_POSTGRES_URL not set")
	}

	ctx := context.Background()
	st, err := store.ConnectPostgres(ctx, url)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer st.Close()

	tenant := &domain.Tenant{
		ID:          uuid.New(),
		Slug:        "ticket-test-" + uuid.New().String()[:8],
		DisplayName: "Ticket Automation Test",
	}
	if err := st.CreateTenant(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	findingID := uuid.New()
	policyID := domain.PolicyTicketOnCriticalID
	action := domain.ActionCreateTicket

	// First reservation must succeed (true)
	first, err := st.ReserveAction(ctx, tenant.ID, policyID, findingID, action)
	if err != nil {
		t.Fatalf("first ReserveAction failed: %v", err)
	}
	if !first {
		t.Errorf("expected first reservation to return true, got false")
	}

	// Second reservation for same (tenant, policy, finding, action) must return false (idempotent, D25)
	second, err := st.ReserveAction(ctx, tenant.ID, policyID, findingID, action)
	if err != nil {
		t.Fatalf("second ReserveAction failed: %v", err)
	}
	if second {
		t.Errorf("expected second reservation to return false (already reserved), got true")
	}

	// Different action on same finding must succeed
	diffAction, err := st.ReserveAction(ctx, tenant.ID, policyID, findingID, "notify_slack")
	if err != nil {
		t.Fatalf("different action ReserveAction failed: %v", err)
	}
	if !diffAction {
		t.Errorf("expected different action to return true, got false")
	}
}

