package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// D123 on PostgreSQL: an attestation that ends within 14 days is announced once, then once more within a day; only the
// current "passed" attestation of a control counts; the owner is kept and named.
func TestAttestation_ExpiryReminders_OnPostgreSQL(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	add := func(control, status, owner string, attestedAgo, expiresIn time.Duration) {
		t.Helper()
		err := h.store.AddAttestation(ctx, h.tenant, store.Attestation{ID: uuid.New(), FrameworkID: "acme", ControlID: control, Status: status, Note: "n",
			AttestedBy: "user:sara@acme.example", Owner: owner, AttestedAt: now.Add(-attestedAgo), ExpiresAt: now.Add(expiresIn)})
		if err != nil {
			t.Fatal(err)
		}
	}
	add("TM-1", "passed", "team:appsec", 24*time.Hour, 10*24*time.Hour) // ends in 10 days: announced at 14
	add("TM-2", "passed", "", 24*time.Hour, 40*24*time.Hour)            // far off: nothing
	add("TM-3", "failed", "", 24*time.Hour, 5*24*time.Hour)             // nothing to renew
	add("TM-4", "passed", "", 48*time.Hour, 5*24*time.Hour)             // superseded by the next one
	add("TM-4", "passed", "", 24*time.Hour, 200*24*time.Hour)           // the current one ends far off: nothing
	add("TM-5", "passed", "", 24*time.Hour, -time.Hour)                 // already ended: not a warning

	built := 0
	got, note, err := h.store.WarnExpiringAttestations(ctx, h.tenant, now, func(l []domain.ExpiringAttestation) *domain.Notification {
		built++
		return &domain.Notification{Kind: domain.NotifyAttestationEnding, Title: "t", Body: l[0].ControlID}
	})
	if err != nil || len(got) != 1 {
		t.Fatalf("one attestation is announced: %+v %v", got, err)
	}
	if e := got[0]; e.ControlID != "TM-1" || e.DaysLeft != 14 || e.Owner != "team:appsec" {
		t.Fatalf("TM-1 at 14 days with its owner: %+v", e)
	}
	if note == nil || built != 1 {
		t.Fatalf("the message is made with the marker: %v %d", note, built)
	}
	list, _, _ := h.store.ListNotifications(ctx, h.tenant, "u", 50)
	found := false
	for _, n := range list {
		found = found || n.Kind == domain.NotifyAttestationEnding && n.Body == "TM-1"
	}
	if !found {
		t.Fatalf("the notification was written in the same transaction: %+v", list)
	}
	if again, _, _ := h.store.WarnExpiringAttestations(ctx, h.tenant, now, nil); len(again) != 0 {
		t.Fatalf("each threshold is announced once: %+v", again)
	}
	// a day before it ends: announced again, and the owner defaults to who made it
	add("TM-6", "passed", "", 24*time.Hour, 10*24*time.Hour-2*time.Hour) // ends a little before TM-1
	later := now.Add(10*24*time.Hour - 12*time.Hour)
	got, _, err = h.store.WarnExpiringAttestations(ctx, h.tenant, later, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("TM-1 and TM-6 are both within a day: %+v %v", got, err)
	}
	for _, e := range got {
		if e.DaysLeft != 1 {
			t.Errorf("%s within a day: %+v", e.ControlID, e)
		}
		if e.ControlID == "TM-6" && e.Owner != "user:sara@acme.example" {
			t.Errorf("no owner named: the person who made it, got %q", e.Owner)
		}
	}
}

// An attestation of one application whose control a whole-tenant attestation still covers, beyond its end, is no news:
// the reading falls back to the tenant-wide one, so neither a reminder nor a ticket is made for it.
func TestAttestation_CoveredByTenantWide_NoReminderNoTicket(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedFindings(t, ctx, h.store, h.tenant, 0) // creates the application "shop"
	app, err := h.store.LookupApplication(ctx, h.tenant, "shop")
	if err != nil || app == nil {
		t.Fatalf("the application: %v %v", app, err)
	}
	add := func(control string, appID *uuid.UUID, expiresIn time.Duration) {
		t.Helper()
		if err := h.store.AddAttestation(ctx, h.tenant, store.Attestation{ID: uuid.New(), FrameworkID: "acme", ControlID: control, ApplicationID: appID, Status: "passed", Note: "n",
			AttestedBy: "user:sara@acme.example", AttestedAt: now.Add(-time.Hour), ExpiresAt: now.Add(expiresIn)}); err != nil {
			t.Fatal(err)
		}
	}
	add("CV-1", &app.ID, 5*24*time.Hour) // the application's, ends soon ...
	add("CV-1", nil, 200*24*time.Hour)   // ... the whole tenant's holds long after: covered
	add("CV-2", &app.ID, 5*24*time.Hour) // the application's, ends soon, nothing covers it
	add("CV-3", &app.ID, 5*24*time.Hour) // the tenant-wide one ends before the application's: it does not cover
	add("CV-3", nil, 2*24*time.Hour)

	got, _, err := h.store.WarnExpiringAttestations(ctx, h.tenant, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range got {
		ids[e.ControlID] = true
	}
	if ids["CV-1"] || !ids["CV-2"] || !ids["CV-3"] {
		t.Fatalf("reminders: want CV-2 and CV-3 only (and CV-3's tenant-wide one), got %v", ids)
	}
	work, _ := h.sys.ListAttestationTicketWork(ctx, now, 14*24*time.Hour, 1000)
	tickets := map[string]bool{}
	for _, w := range work {
		if w.TenantID == h.tenant {
			tickets[w.ControlID] = true
		}
	}
	if tickets["CV-1"] || !tickets["CV-2"] {
		t.Fatalf("tickets: CV-1 is covered, CV-2 is not: %v", tickets)
	}
}
