package store_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
)

// tenantTracker counts only the calls for one tenant: the outbox is read across tenants, and other tests in the
// same database leave their own reservations.
type tenantTracker struct {
	fakeTracker
	tenant uuid.UUID
	mine   int
}

func (t *tenantTracker) CreateIssue(ctx context.Context, f *domain.Finding, app string) (string, string, error) {
	if f.TenantID == t.tenant {
		t.mine++
	}
	return t.fakeTracker.CreateIssue(ctx, f, app)
}

// D90 (docs/23 C8): one ticket per correlation group, and one ticket for a finding group, on PostgreSQL.
func TestGroupAndCorrelationTickets_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tn := &domain.Tenant{ID: uuid.New(), Slug: "gt-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	mk := func(title, corr string) *domain.Finding {
		f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "semgrep", RuleID: "r", Title: title, Category: domain.CategorySAST, Severity: domain.SeverityCritical, ToolSeverity: "critical",
			State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now, CorrelationKey: corr}
		if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{f}); err != nil {
			t.Fatal(err)
		}
		return f
	}
	has := func(f uuid.UUID, ref string) bool {
		b, err := appStore.FindingHasTicket(ctx, tn.ID, f, "", ref)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// Two tools report the same issue (same correlation key): the second is linked to the first one's ticket.
	semgrep, codeql := mk("SQL injection (semgrep)", "corr-sqli"), mk("SQL injection (codeql)", "corr-sqli")
	for _, f := range []*domain.Finding{semgrep, codeql} {
		if ok, err := appStore.ReserveAction(ctx, tn.ID, domain.PolicyTicketOnCriticalID, f.ID, domain.ActionCreateTicket); err != nil || !ok {
			t.Fatalf("reserve: %v %v", ok, err)
		}
	}
	tr := &tenantTracker{tenant: tn.ID}
	connectors.ProcessTickets(ctx, sys, fakeResolver{tr}, now.Add(time.Minute), log)
	if tr.mine != 1 || !has(semgrep.ID, "SEC-7") || !has(codeql.ID, "SEC-7") {
		t.Fatalf("one ticket for the correlation group: %d calls", tr.mine)
	}

	// A finding group: the API reserves, the sweeper opens one ticket and links every member.
	a, b := mk("XSS in cart", ""), mk("XSS in search", "")
	grp := &domain.FindingGroup{TenantID: tn.ID, Name: "XSS sprint", ApplicationID: &app.ID}
	if err := appStore.CreateFindingGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	if err := appStore.AddGroupMembers(ctx, tn.ID, grp.ID, []uuid.UUID{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if apps, err := appStore.GroupMemberApplications(ctx, tn.ID, grp.ID); err != nil || len(apps) != 1 || apps[0] != app.ID {
		t.Fatalf("member applications: %v %v", apps, err)
	}
	if ok, err := appStore.RequestGroupTicket(ctx, tn.ID, grp.ID, "user:alice"); err != nil || !ok {
		t.Fatalf("request: %v %v", ok, err)
	}
	if ok, _ := appStore.RequestGroupTicket(ctx, tn.ID, grp.ID, "user:alice"); ok {
		t.Fatal("a second request while one is reserved")
	}
	if p, _ := appStore.ListPendingGroupTickets(ctx, now.Add(time.Hour), 10); len(p) != 0 {
		t.Fatal("the application role must not read the outbox across tenants")
	}
	tr2 := &tenantTracker{tenant: tn.ID}
	gs := connectors.GroupTicketStore(sys)
	connectors.ProcessGroupTickets(ctx, gs, fakeResolver{tr2}, now.Add(time.Hour), log)
	if tr2.mine != 1 {
		t.Fatalf("one group ticket: %d calls", tr2.mine)
	}
	if !has(a.ID, "SEC-7") || !has(b.ID, "SEC-7") {
		t.Fatal("the group's ticket is linked to every member")
	}
	got, err := appStore.GetFindingGroup(ctx, tn.ID, grp.ID)
	if err != nil || got.Ticket == nil || got.Ticket.Status != "done" || got.Ticket.ExternalRef != "SEC-7" || got.ApplicationID == nil {
		t.Fatalf("group after: %+v %v", got, err)
	}
	connectors.ProcessGroupTickets(ctx, gs, fakeResolver{tr2}, now.Add(2*time.Hour), log)
	if tr2.mine != 1 {
		t.Fatal("a done group ticket is not opened again")
	}
}
