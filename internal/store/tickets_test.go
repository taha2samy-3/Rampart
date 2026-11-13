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
func (f *fakeTracker) FindIssueByLabel(context.Context, string) (string, string, error) {
	return "", "", nil
}

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

func TestTicketTable_MultiTracker_Grouping_Reactivation_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)

	tnA := &domain.Tenant{ID: uuid.New(), Slug: "tka-" + uuid.NewString()[:8], DisplayName: "Tenant A", CreatedAt: time.Now().UTC()}
	tnB := &domain.Tenant{ID: uuid.New(), Slug: "tkb-" + uuid.NewString()[:8], DisplayName: "Tenant B", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tnA); err != nil {
		t.Fatal(err)
	}
	if err := sys.CreateTenant(ctx, tnB); err != nil {
		t.Fatal(err)
	}

	seedFindings(t, ctx, appStore, tnA.ID, 0)
	seedFindings(t, ctx, appStore, tnB.ID, 0)
	appA, _ := appStore.LookupApplication(ctx, tnA.ID, "shop")
	assetA, _ := appStore.LookupAsset(ctx, tnA.ID, domain.AssetRepository, "github.com/acme/shop")

	now := time.Now().UTC()
	f1 := &domain.Finding{ID: uuid.New(), TenantID: tnA.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: assetA.ID, ApplicationID: appA.ID, Track: "main",
		RuleScannerFamily: "semgrep", RuleID: "r1", Title: "Crit 1", Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
		State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}
	f2 := &domain.Finding{ID: uuid.New(), TenantID: tnA.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: assetA.ID, ApplicationID: appA.ID, Track: "main",
		RuleScannerFamily: "semgrep", RuleID: "r2", Title: "Crit 2", Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
		State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}

	if err := appStore.UpsertFindings(ctx, tnA.ID, []*domain.Finding{f1, f2}); err != nil {
		t.Fatal(err)
	}

	// 1. Two trackers on one finding (D70 B1): Jira & GitHub
	tJira, err := appStore.CreateTicket(ctx, tnA.ID, &domain.Ticket{
		Connector:   "jira",
		ExternalRef: "SEC-101",
		URL:         "https://jira.example/browse/SEC-101",
		State:       "open",
	})
	if err != nil {
		t.Fatalf("CreateTicket jira failed: %v", err)
	}
	tGH, err := appStore.CreateTicket(ctx, tnA.ID, &domain.Ticket{
		Connector:   "github",
		ExternalRef: "#42",
		URL:         "https://github.com/acme/shop/issues/42",
		State:       "open",
	})
	if err != nil {
		t.Fatalf("CreateTicket github failed: %v", err)
	}

	if err := appStore.LinkFinding(ctx, tnA.ID, tJira.ID, f1.ID); err != nil {
		t.Fatalf("LinkFinding f1 -> tJira failed: %v", err)
	}
	if err := appStore.LinkFinding(ctx, tnA.ID, tGH.ID, f1.ID); err != nil {
		t.Fatalf("LinkFinding f1 -> tGH failed: %v", err)
	}

	tickets, err := appStore.TicketsOfFinding(ctx, tnA.ID, f1.ID)
	if err != nil {
		t.Fatalf("TicketsOfFinding failed: %v", err)
	}
	if len(tickets) != 2 {
		t.Fatalf("expected 2 tickets on f1, got %d", len(tickets))
	}

	// 2. One ticket on two findings (grouping, D70 B1): link f2 to tJira
	if err := appStore.LinkFinding(ctx, tnA.ID, tJira.ID, f2.ID); err != nil {
		t.Fatalf("LinkFinding f2 -> tJira failed: %v", err)
	}
	hasF1Jira, _ := appStore.FindingHasTicket(ctx, tnA.ID, f1.ID, "SEC-101")
	hasF2Jira, _ := appStore.FindingHasTicket(ctx, tnA.ID, f2.ID, "SEC-101")
	if !hasF1Jira || !hasF2Jira {
		t.Fatalf("one ticket covers both findings: f1=%v, f2=%v", hasF1Jira, hasF2Jira)
	}

	// 3. Reactivated finding: f1 is fixed, then later a new ticket JIRA-2 is opened
	if err := appStore.SetTicketState(ctx, tnA.ID, tJira.ID, "closed"); err != nil {
		t.Fatalf("SetTicketState failed: %v", err)
	}
	tJira2, err := appStore.CreateTicket(ctx, tnA.ID, &domain.Ticket{
		Connector:   "jira",
		ExternalRef: "SEC-202",
		URL:         "https://jira.example/browse/SEC-202",
		State:       "open",
	})
	if err != nil {
		t.Fatalf("CreateTicket jira2 failed: %v", err)
	}
	if err := appStore.LinkFinding(ctx, tnA.ID, tJira2.ID, f1.ID); err != nil {
		t.Fatalf("LinkFinding f1 -> tJira2 failed: %v", err)
	}
	hasReactivated, _ := appStore.FindingHasTicket(ctx, tnA.ID, f1.ID, "SEC-202")
	if !hasReactivated {
		t.Fatal("reactivated finding has new ticket SEC-202")
	}

	// 4. Verifier answers per ticket
	hasUnknown, _ := appStore.FindingHasTicket(ctx, tnA.ID, f1.ID, "SEC-999")
	if hasUnknown {
		t.Fatal("unknown ticket must answer false")
	}

	// 5. Tenant isolation: tenantB cannot read tenantA's tickets or link findings across tenants
	ticketsB, err := appStore.TicketsOfFinding(ctx, tnB.ID, f1.ID)
	if err != nil {
		t.Fatalf("TicketsOfFinding under tenantB: %v", err)
	}
	if len(ticketsB) != 0 {
		t.Fatalf("tenant isolation broken: tenantB saw tenantA tickets: %d", len(ticketsB))
	}
	hasB, _ := appStore.FindingHasTicket(ctx, tnB.ID, f1.ID, "SEC-101")
	if hasB {
		t.Fatal("tenantB must not verify tenantA's ticket")
	}
}

func TestProcessTickets_LookupBeforeRetry_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tn := &domain.Tenant{ID: uuid.New(), Slug: "lookup-" + uuid.NewString()[:8], DisplayName: "Tenant Lookup", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
		RuleScannerFamily: "semgrep", RuleID: "r", Title: "Crit Ambiguous", Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
		State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}

	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if ok, err := appStore.ReserveAction(ctx, tn.ID, domain.PolicyTicketOnCriticalID, f.ID, domain.ActionCreateTicket); err != nil || !ok {
		t.Fatalf("reserve: %v %v", ok, err)
	}

	// Tracker creates ticket on attempt 1, but network times out returning 504
	failingTracker := &ambiguousTracker{
		createdRef: "SEC-AMBIGUOUS-1",
		createdURL: "https://jira.example/browse/SEC-AMBIGUOUS-1",
	}

	// Sweep 1: attempt 1 fails
	opened, failed := connectors.ProcessTickets(ctx, sys, fakeResolver{failingTracker}, now.Add(time.Minute), log)
	if opened != 0 || failed != 1 {
		t.Fatalf("sweep 1: opened %d, failed %d", opened, failed)
	}

	// Sweep 2: attempt > 0, FindIssueByLabel finds the ticket created in attempt 1!
	clock := now.Add(10 * time.Minute)
	opened2, failed2 := connectors.ProcessTickets(ctx, sys, fakeResolver{failingTracker}, clock, log)
	if opened2 != 1 || failed2 != 0 {
		t.Fatalf("sweep 2: opened %d, failed %d", opened2, failed2)
	}

	// Exactly one ticket was created in external tracker (no duplicate)
	if failingTracker.createCalls != 1 {
		t.Fatalf("expected exactly 1 CreateIssue call, got %d", failingTracker.createCalls)
	}
	has, _ := appStore.FindingHasTicket(ctx, tn.ID, f.ID, "SEC-AMBIGUOUS-1")
	if !has {
		t.Fatal("expected ticket to be recorded via FindIssueByLabel")
	}
}

type ambiguousTracker struct {
	createCalls int
	createdRef  string
	createdURL  string
}

func (a *ambiguousTracker) CreateIssue(ctx context.Context, f *domain.Finding, app string) (string, string, error) {
	a.createCalls++
	return "", "", errors.New("gateway timeout 504")
}

func (a *ambiguousTracker) FindIssueByLabel(ctx context.Context, label string) (string, string, error) {
	if a.createCalls > 0 {
		return a.createdRef, a.createdURL, nil
	}
	return "", "", nil
}

func (a *ambiguousTracker) Check(ctx context.Context) error { return nil }

func TestProcessTickets_FatalErrorsGiveUp_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tn := &domain.Tenant{ID: uuid.New(), Slug: "fatal-" + uuid.NewString()[:8], DisplayName: "Tenant Fatal", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
		RuleScannerFamily: "semgrep", RuleID: "r", Title: "Crit Fatal", Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
		State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}

	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if ok, err := appStore.ReserveAction(ctx, tn.ID, domain.PolicyTicketOnCriticalID, f.ID, domain.ActionCreateTicket); err != nil || !ok {
		t.Fatalf("reserve: %v %v", ok, err)
	}

	// Register a Jira connector so we can verify Connected condition turns False on 403
	conn := domain.Connector{
		Name:     "jira-prod",
		TenantID: tn.ID,
		Type:     domain.ConnectorTypeJira,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeJira,
			Jira:      &domain.JiraConnectorConfig{URL: "https://jira.acme.com", DefaultProject: "SEC"},
			Ticketing: &domain.ConnectorTicketingPolicy{OnCritical: true},
		},
	}
	conn.SetCondition("Connected", "True", "AuthOK", "Ready")
	if err := sys.SaveConnector(ctx, tn.ID, conn); err != nil {
		t.Fatal(err)
	}

	fatalTracker := &fatalTrackerStub{err: &domain.TrackerError{Status: 403, Message: "Forbidden: invalid credentials"}}

	// Attempt 1: 403 error is fatal (D70 B4) -> give up immediately!
	opened, failed := connectors.ProcessTickets(ctx, sys, fakeResolver{fatalTracker}, now.Add(time.Minute), log)
	if opened != 0 || failed != 1 {
		t.Fatalf("opened %d, failed %d", opened, failed)
	}

	// Check that reservation is already failed (attempts = 1, giveUp = true)
	pending, err := sys.ListPendingTickets(ctx, now.Add(48*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.FindingID == f.ID {
			t.Fatal("fatal error must not remain in pending queue")
		}
	}

	// Check connector condition turned Connected=False with AuthFailed
	savedConn, err := sys.GetConnector(ctx, tn.ID, "jira-prod")
	if err != nil {
		t.Fatal(err)
	}
	cond := savedConn.GetCondition("Connected")
	if cond == nil || cond.Status != "False" || cond.Reason != "AuthFailed" {
		t.Fatalf("expected Connected=False/AuthFailed, got %+v", cond)
	}
}

type fatalTrackerStub struct {
	err error
}

func (f *fatalTrackerStub) CreateIssue(ctx context.Context, finding *domain.Finding, app string) (string, string, error) {
	return "", "", f.err
}

func (f *fatalTrackerStub) FindIssueByLabel(ctx context.Context, label string) (string, string, error) {
	return "", "", nil
}

func (f *fatalTrackerStub) Check(ctx context.Context) error { return nil }
