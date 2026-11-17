package store_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/store"
)

type renewalTracker struct {
	created   []*domain.Finding
	closed    []string
	commented []string
	failNext  error
	found     string // what FindIssueByLabel answers
}

func (r *renewalTracker) Name() string { return "jira" }
func (r *renewalTracker) CreateIssue(_ context.Context, f *domain.Finding, _ string) (string, string, error) {
	if r.failNext != nil {
		err := r.failNext
		r.failNext = nil
		return "", "", err
	}
	r.created = append(r.created, f)
	return "SEC-" + uuid.NewString()[:4], "https://jira.example/browse/SEC", nil
}
func (r *renewalTracker) FindIssueByLabel(context.Context, string) (string, string, error) {
	return r.found, "https://jira.example/browse/" + r.found, nil
}
func (r *renewalTracker) Comment(_ context.Context, ref, _ string) error {
	r.commented = append(r.commented, ref)
	return nil
}
func (r *renewalTracker) Close(_ context.Context, ref string) error {
	r.closed = append(r.closed, ref)
	return nil
}
func (r *renewalTracker) Check(context.Context) error { return nil }

// forTenant serves a tracker to one tenant only: the database is shared with other tests, and the sweeper reads across
// tenants, as it must.
type forTenant struct {
	tenant uuid.UUID
	t      domain.Tracker
}

func (f forTenant) ResolveTracker(_ context.Context, id uuid.UUID) (domain.Tracker, error) {
	if id != f.tenant {
		return nil, nil
	}
	return f.t, nil
}

type noTracker struct{}

func (noTracker) ResolveTracker(context.Context, uuid.UUID) (domain.Tracker, error) { return nil, nil }

// D124 on PostgreSQL: an attestation that ends within 14 days gets one renewal ticket on the tenant's tracker, with the
// owner named; a tenant without a tracker gets none and nothing waits for one; a failed call is retried and finds the
// issue by its label first; the ticket is closed when the attestation is renewed.
func TestAttestationTickets_OnPostgreSQL(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	add := func(control, status string, attestedAgo, expiresIn time.Duration) {
		t.Helper()
		if err := h.store.AddAttestation(ctx, h.tenant, store.Attestation{ID: uuid.New(), FrameworkID: "acme", ControlID: control, Status: status, Note: "n",
			AttestedBy: "user:sara@acme.example", Owner: "team:appsec", AttestedAt: now.Add(-attestedAgo), ExpiresAt: now.Add(expiresIn)}); err != nil {
			t.Fatal(err)
		}
	}
	add("TM-1", "passed", time.Hour, 10*24*time.Hour) // ends within 14 days: a ticket
	add("TM-2", "passed", time.Hour, 90*24*time.Hour) // far off
	add("TM-3", "failed", time.Hour, 5*24*time.Hour)  // nothing to renew
	process := func(tr domain.TrackerResolver, at time.Time) (int, int, int) {
		return connectors.ProcessAttestationTickets(ctx, h.sys, tr, at, log)
	}

	// no tracker: nothing opens and nothing is reserved
	if o, c, f := process(noTracker{}, now); o+c+f != 0 {
		t.Fatalf("no tracker: %d %d %d", o, c, f)
	}
	var mine []store.AttestationTicketWork
	all, _ := h.sys.ListAttestationTicketWork(ctx, now, connectors.AttestationTicketWindow, 1000)
	for _, w := range all {
		if w.TenantID == h.tenant {
			mine = append(mine, w)
		}
	}
	if len(mine) != 1 || mine[0].ControlID != "TM-1" || mine[0].Owner != "team:appsec" {
		t.Fatalf("TM-1 waits for a tracker: %+v", mine)
	}

	tr := &renewalTracker{failNext: errors.New("connection reset")}
	if _, _, f := process(forTenant{h.tenant, tr}, now); f != 1 || len(tr.created) != 0 {
		t.Fatalf("a failed call is counted and not recorded as opened: failed=%d created=%d", f, len(tr.created))
	}
	// the retry is not due yet
	if o, _, f := process(forTenant{h.tenant, tr}, now); o+f != 0 {
		t.Fatalf("not before the backoff: %d %d", o, f)
	}
	// later: it first asks for the issue by its label (the failed call may have created it), then does not create a second
	tr.found = "SEC-123"
	later := now.Add(time.Hour)
	if o, _, _ := process(forTenant{h.tenant, tr}, later); o != 1 || len(tr.created) != 0 {
		t.Fatalf("the issue found by its label is used: opened=%d created=%d", o, len(tr.created))
	}
	if o, _, _ := process(forTenant{h.tenant, tr}, later.Add(time.Hour)); o != 0 {
		t.Fatalf("one ticket per attestation: %d", o)
	}

	// a new attestation of TM-4 ending soon: the ticket names the control, the owner and the date, and is a notice
	add("TM-4", "passed", time.Minute, 3*24*time.Hour)
	if o, _, _ := process(forTenant{h.tenant, tr}, later.Add(2*time.Hour)); o != 1 || len(tr.created) != 1 {
		t.Fatalf("TM-4: %d %d", o, len(tr.created))
	}
	is := tr.created[0]
	if is.Notice == "" || !strings.Contains(is.Title, "acme / TM-4") || !strings.Contains(is.Description, "Owner: team:appsec") {
		t.Fatalf("the ticket: %+v", is)
	}

	// TM-1 is renewed for a year: its ticket is closed, with a comment, once
	add("TM-1", "passed", 0, 365*24*time.Hour)
	if _, c, _ := process(forTenant{h.tenant, tr}, later.Add(3*time.Hour)); c != 1 || len(tr.closed) != 1 || tr.closed[0] != "SEC-123" || len(tr.commented) != 1 {
		t.Fatalf("renewed: closed=%v commented=%v", tr.closed, tr.commented)
	}
	if _, c, _ := process(forTenant{h.tenant, tr}, later.Add(4*time.Hour)); c != 0 {
		t.Fatalf("closed once: %d", c)
	}

	// A ticket that gives up is not silent: the tenant is told, the attestation shows it, and an administrator (the
	// application role, through the API) can send it back; the sweeper then opens it.
	add("TM-7", "passed", time.Minute, 2*24*time.Hour)
	var tm7 uuid.UUID
	atts, err := h.store.Attestations(ctx, h.tenant, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		if a.ControlID == "TM-7" {
			tm7 = a.ID
		}
	}
	bad := &renewalTracker{failNext: &domain.TrackerError{Status: 401, Message: "bad credentials"}}
	if _, _, f := process(forTenant{h.tenant, bad}, later.Add(5*time.Hour)); f != 1 {
		t.Fatalf("the failure is counted: %d", f)
	}
	notes, _, _ := h.store.ListNotifications(ctx, h.tenant, "u", 50)
	told := false
	for _, n := range notes {
		told = told || n.Kind == "ticket_failed" && strings.Contains(n.Body, "TM-7")
	}
	if !told {
		t.Fatalf("a ticket that gave up is announced: %+v", notes)
	}
	atts, _ = h.store.Attestations(ctx, h.tenant, "acme")
	for _, a := range atts {
		if a.ID == tm7 && (a.Ticket == nil || a.Ticket.Status != "failed" || a.Ticket.Error == "") {
			t.Fatalf("the attestation shows its failed ticket: %+v", a.Ticket)
		}
	}
	if ok, err := h.store.RetryFailedAttestationTicket(ctx, h.tenant, tm7); err != nil || !ok {
		t.Fatalf("sent back by the application role: %v %v", ok, err)
	}
	if ok, _ := h.store.RetryFailedAttestationTicket(ctx, h.tenant, tm7); ok {
		t.Fatal("only a failed ticket goes back")
	}
	good := &renewalTracker{}
	if o, _, _ := process(forTenant{h.tenant, good}, later.Add(6*time.Hour)); o != 1 || len(good.created) != 1 {
		t.Fatalf("the sweeper opens it after the retry: %d %d", o, len(good.created))
	}
}
