package ingest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func TestTicketOnCriticalPlaceholder(t *testing.T) {
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

	// Must contain both "created" and "ticket_created" events
	hasTicket := false
	for _, ev := range events {
		if ev.Type == "ticket_created" {
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
		if ev.Type == "ticket_created" {
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
		if ev.Type == "ticket_created" {
			ticketEventCount++
		}
	}
	if ticketEventCount != 1 {
		t.Errorf("expected exactly 1 ticket_created event after rescan (idempotent), got %d", ticketEventCount)
	}
}

type mockTracker struct {
	createdCount int
}

func (m *mockTracker) CreateIssue(_ context.Context, f *domain.Finding, appName string) (string, string, error) {
	m.createdCount++
	return "SEC-101", "https://jira.example.com/browse/SEC-101", nil
}

func (m *mockTracker) Check(_ context.Context) error {
	return nil
}

type mockTrackerResolver struct {
	tracker ingest.Tracker
}

func (m *mockTrackerResolver) ResolveTracker(_ context.Context, _ uuid.UUID) (ingest.Tracker, error) {
	return m.tracker, nil
}

func TestTicketOnCritical_WithActiveTracker(t *testing.T) {
	ctx := context.Background()
	mem := ingest.NewMemoryStore()
	eng := ingest.NewEngine(mem)

	tracker := &mockTracker{}
	resolver := &mockTrackerResolver{tracker: tracker}
	eng.SetTrackerResolver(resolver)

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
			FindingKey:    "f-crit-tracker",
			RuleID:        "remote-code-exec",
			Title:         "Remote Code Execution",
			Severity:      domain.SeverityCritical,
			SeenAt:        time.Now().UTC(),
			Location: domain.Location{
				Code: &domain.CodeLocation{
					FilePath:  "cmd/server.go",
					StartLine: 15,
				},
			},
		},
	}

	// 1. Merge creates critical finding and triggers tracker.CreateIssue
	_, err := eng.MergeBatch(ctx, scope, runID, appID, records)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}

	if tracker.createdCount != 1 {
		t.Fatalf("expected tracker.CreateIssue to be called once, called %d times", tracker.createdCount)
	}

	fs, err := mem.GetFindingsByKeys(ctx, tenantID, []string{"f-crit-tracker"})
	if err != nil || fs["f-crit-tracker"] == nil {
		t.Fatalf("finding not found: %v", err)
	}

	events, err := mem.GetFindingEvents(ctx, tenantID, fs["f-crit-tracker"].ID)
	if err != nil {
		t.Fatalf("get events failed: %v", err)
	}

	foundTicketEvent := false
	for _, ev := range events {
		if ev.Type == "ticket_created" {
			foundTicketEvent = true
			if !strings.Contains(ev.Note, "SEC-101") {
				t.Errorf("expected note to contain 'SEC-101', got %q", ev.Note)
			}
			if !strings.Contains(string(ev.To), `"status":"created"`) {
				t.Errorf("expected status 'created' in event.To, got %s", string(ev.To))
			}
		}
	}
	if !foundTicketEvent {
		t.Errorf("expected ticket_created event, found none")
	}

	// 2. Rescan must be idempotent and NOT call tracker.CreateIssue again (D25, D66)
	_, err = eng.MergeBatch(ctx, scope, uuid.New(), appID, records)
	if err != nil {
		t.Fatalf("second merge failed: %v", err)
	}
	if tracker.createdCount != 1 {
		t.Errorf("rescan called tracker.CreateIssue again! count=%d", tracker.createdCount)
	}
}
