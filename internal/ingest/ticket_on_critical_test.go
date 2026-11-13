package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

// The merge only reserves the ticket of a critical finding (docs/16 D70): no call to a tracker is made inside the
// transaction, and the reservation is made once however often the finding is scanned.
func TestTicketOnCriticalReservesOnlyOnce(t *testing.T) {
	ctx := context.Background()
	mem := ingest.NewMemoryStore()
	eng := ingest.NewEngine(mem)

	tenantID := uuid.New()
	appID := uuid.New()
	assetID := uuid.New()
	runID := uuid.New()

	scope := domain.CloseScope{
		TenantID:      tenantID,
		AssetID:       assetID,
		ScannerFamily: "semgrep",
		Track:         "default",
	}

	records := []ingest.StagedRecord{
		{
			ScannerFamily: "semgrep",
			FindingKey:    "f-critical-1",
			RuleID:        "sql-injection",
			Title:         "SQL Injection Vulnerability",
			Severity:      domain.SeverityCritical,
			SeenAt:        time.Now().UTC(),
			Location: domain.Location{
				Code: &domain.CodeLocation{
					FilePath:  "db/query.go",
					StartLine: 42,
				},
			},
		},
		{
			ScannerFamily: "semgrep",
			FindingKey:    "f-medium-1",
			RuleID:        "hardcoded-tmp",
			Title:         "Insecure temp file",
			Severity:      domain.SeverityMedium,
			SeenAt:        time.Now().UTC(),
			Location: domain.Location{
				Code: &domain.CodeLocation{
					FilePath:  "tmp/file.go",
					StartLine: 10,
				},
			},
		},
	}

	// 1. Initial merge of the critical and medium findings
	outcome, err := eng.MergeBatch(ctx, scope, runID, appID, records)
	if err != nil {
		t.Fatalf("first merge failed: %v", err)
	}
	if outcome.Created != 2 {
		t.Fatalf("expected 2 created findings, got %d", outcome.Created)
	}

	fs, err := mem.GetFindingsByKeys(ctx, tenantID, []string{"f-critical-1", "f-medium-1"})
	if err != nil {
		t.Fatalf("get findings by keys: %v", err)
	}
	fCrit := fs["f-critical-1"]
	if fCrit == nil {
		t.Fatalf("critical finding not found")
	}

	events, err := mem.GetFindingEvents(ctx, tenantID, fCrit.ID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}

	// Must contain the reservation event
	hasTicket := false
	for _, ev := range events {
		if ev.Type == "ticket_requested" {
			hasTicket = true
			if ev.Actor != "system:policy" {
				t.Errorf("expected actor 'system:policy', got %q", ev.Actor)
			}
		}
	}
	if !hasTicket {
		t.Errorf("critical finding missing 'ticket_created' event")
	}

	// Medium finding must NOT have ticket_created event
	fMed := fs["f-medium-1"]
	if fMed == nil {
		t.Fatalf("medium finding not found")
	}
	medEvents, err := mem.GetFindingEvents(ctx, tenantID, fMed.ID)
	if err != nil {
		t.Fatalf("get medium events: %v", err)
	}
	for _, ev := range medEvents {
		if ev.Type == "ticket_requested" {
			t.Errorf("medium finding unexpectedly received ticket_created event")
		}
	}

	// 2. Rescan with the same critical finding (idempotency test, D25)
	runID2 := uuid.New()
	_, err = eng.MergeBatch(ctx, scope, runID2, appID, records)
	if err != nil {
		t.Fatalf("second merge failed: %v", err)
	}

	eventsAfter, err := mem.GetFindingEvents(ctx, tenantID, fCrit.ID)
	if err != nil {
		t.Fatalf("get events after rescan: %v", err)
	}

	ticketEventCount := 0
	for _, ev := range eventsAfter {
		if ev.Type == "ticket_requested" {
			ticketEventCount++
		}
	}
	if ticketEventCount != 1 {
		t.Errorf("expected exactly 1 ticket_created event after rescan (idempotent), got %d", ticketEventCount)
	}
}
