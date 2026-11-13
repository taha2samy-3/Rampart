package store_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
)

type fakeTracker struct {
	calls int
	err   error
}

func (f *fakeTracker) CreateIssue(context.Context, *domain.Finding, string) (string, string, error) {
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	return "SEC-7", "https://jira.example/browse/SEC-7", nil
}
func (f *fakeTracker) Check(context.Context) error { return nil }

type fakeResolver struct{ t domain.Tracker }

func (f fakeResolver) ResolveTracker(context.Context, uuid.UUID) (domain.Tracker, error) {
	return f.t, nil
}

func TestTicketOutbox_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tn := &domain.Tenant{ID: uuid.New(), Slug: "tk-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	mk := func(i int) *domain.Finding {
		return &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "semgrep", RuleID: "r", Title: "Critical " + string(rune('A'+i)), Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
			State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}
	}
	reserve := func(f *domain.Finding) {
		if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{f}); err != nil {
			t.Fatal(err)
		}
		if ok, err := appStore.ReserveAction(ctx, tn.ID, domain.PolicyTicketOnCriticalID, f.ID, domain.ActionCreateTicket); err != nil || !ok {
			t.Fatalf("reserve: %v %v", ok, err)
		}
	}
	pendingOf := func(at time.Time) int {
		p, err := sys.ListPendingTickets(ctx, at, 100)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, x := range p {
			if x.TenantID == tn.ID {
				n++
			}
		}
		return n
	}

	// Reserved once however often it is asked; the system role sees it, the application role sees nothing (row-level
	// security), which is why the sweeper is started only with the system role.
	ok := mk(0)
	reserve(ok)
	if again, _ := appStore.ReserveAction(ctx, tn.ID, domain.PolicyTicketOnCriticalID, ok.ID, domain.ActionCreateTicket); again {
		t.Fatal("a second reservation must not be made")
	}
	if pendingOf(now.Add(time.Second)) != 1 {
		t.Fatal("the reservation must be pending")
	}
	if p, _ := appStore.ListPendingTickets(ctx, now.Add(time.Second), 100); len(p) != 0 {
		t.Fatalf("the application role must not read across tenants: %d", len(p))
	}

	// No tracker yet: the ticket waits, is not counted as an attempt, and is given up after the grace period.
	opened, failed := connectors.ProcessTickets(ctx, sys, fakeResolver{}, now.Add(time.Minute), log)
	if opened != 0 || failed != 0 || pendingOf(now.Add(time.Minute)) != 0 || pendingOf(now.Add(15*time.Minute)) != 1 {
		t.Fatalf("with no tracker the ticket waits: opened %d failed %d", opened, failed)
	}
	connectors.ProcessTickets(ctx, sys, fakeResolver{}, now.Add(connectors.TicketGrace+time.Hour), log)
	if pendingOf(now.Add(48*time.Hour)) != 0 {
		t.Fatal("after the grace period with no tracker the reservation is closed, not kept for ever")
	}

	// A tracker that works: one ticket, recorded, tied to the finding, and never opened again.
	good := mk(1)
	reserve(good)
	tr := &fakeTracker{}
	at := now.Add(2 * time.Minute)
	if opened, _ := connectors.ProcessTickets(ctx, sys, fakeResolver{tr}, at, log); opened != 1 || tr.calls != 1 {
		t.Fatalf("one ticket: opened %d calls %d", opened, tr.calls)
	}
	connectors.ProcessTickets(ctx, sys, fakeResolver{tr}, at.Add(time.Hour), log)
	if tr.calls != 1 {
		t.Fatalf("a ticket already opened is not opened again: %d calls", tr.calls)
	}
	has := func(f uuid.UUID, ref string) bool {
		b, err := appStore.FindingHasTicket(ctx, tn.ID, f, ref)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if !has(good.ID, "SEC-7") || has(good.ID, "SEC-8") || has(ok.ID, "SEC-7") || has(uuid.New(), "SEC-7") {
		t.Fatal("a ticket belongs to the finding it was opened for, and to no other")
	}
	evs, _ := sys.GetFindingEvents(ctx, tn.ID, good.ID)
	created := 0
	for _, e := range evs {
		if e.Type == "ticket_created" {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("the timeline says once that the ticket was opened: %d", created)
	}

	// A tracker that fails: each attempt waits longer, and after the last a person is told.
	bad := mk(2)
	reserve(bad)
	failing := &fakeTracker{err: errors.New("jira: issue creation returned status 500")}
	clock := now.Add(3 * time.Minute)
	for i := 0; i < connectors.MaxTicketAttempts; i++ {
		_, f := connectors.ProcessTickets(ctx, sys, fakeResolver{failing}, clock, log)
		if f != 1 {
			t.Fatalf("attempt %d: %d failures", i+1, f)
		}
		if pendingOf(clock) != 0 && i < connectors.MaxTicketAttempts-1 {
			t.Fatalf("attempt %d: the next attempt must wait", i+1)
		}
		clock = clock.Add(7 * time.Hour) // later than any wait
	}
	if failing.calls != connectors.MaxTicketAttempts || pendingOf(clock.Add(24*time.Hour)) != 0 {
		t.Fatalf("given up after %d attempts: calls %d", connectors.MaxTicketAttempts, failing.calls)
	}
	var failedEvents int
	evs, _ = sys.GetFindingEvents(ctx, tn.ID, bad.ID)
	for _, e := range evs {
		if e.Type == "ticket_failed" {
			failedEvents++
		}
	}
	notes, unread, _ := sys.ListNotifications(ctx, tn.ID, "someone", 10)
	if failedEvents != 1 || unread != 1 || len(notes) != 1 || notes[0].Kind != "ticket_failed" {
		t.Fatalf("a person is told once: events %d, notifications %+v", failedEvents, notes)
	}

	// A finding fixed before its turn needs no ticket.
	gone := mk(3)
	reserve(gone)
	gone.State = domain.StateFixed
	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{gone}); err != nil {
		t.Fatal(err)
	}
	tr2 := &fakeTracker{}
	connectors.ProcessTickets(ctx, sys, fakeResolver{tr2}, clock.Add(time.Hour), log)
	if tr2.calls != 0 {
		t.Fatalf("no ticket for a finding that is no longer open: %d", tr2.calls)
	}
}
