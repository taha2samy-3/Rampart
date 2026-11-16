package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// D92 on PostgreSQL: the webhook finds its source with no tenant, the source's Dependency-Track block round-trips,
// a hand mapping survives the next sync, a decision is new once, and a sync whose worker died does not block for ever.
func TestDTrackWiring_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "dt-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	srcID, err := appStore.SaveScanSource(ctx, tn.ID, "dtrack-portfolio", "dependency-track", nil)
	if err != nil {
		t.Fatal(err)
	}

	// The webhook lookup runs as the application role with no tenant (migration 40's policy).
	if gotTenant, name, err := appStore.LookupScanSource(ctx, srcID); err != nil || gotTenant != tn.ID || name != "dtrack-portfolio" {
		t.Fatalf("webhook lookup: %v %v %q", gotTenant, err, name)
	}
	if _, _, err := appStore.LookupScanSource(ctx, uuid.New()); err == nil {
		t.Fatal("an unknown id is not found")
	}

	spec := json.RawMessage(`{"projects":{"versions":"all","tags":["team-a"]},"webhook":{"enabled":true},"triageSync":{"trustUpstreamDecisions":true}}`)
	if err := appStore.SaveDTrackSource(ctx, tn.ID, srcID, "dtrack", spec, 45*time.Minute); err != nil {
		t.Fatal(err)
	}
	src, err := appStore.GetDTrackSource(ctx, tn.ID, srcID)
	if err != nil || src.Connector != "dtrack" || src.Schedule != 45*time.Minute || src.Spec.Versions() != "all" || !src.Spec.Webhook.Enabled {
		t.Fatalf("source: %+v %v", src, err)
	}
	all, err := sys.ListDTrackSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range all {
		found = found || s.ID == srcID
	}
	if !found {
		t.Fatal("the system role lists every tenant's sources")
	}
	if st, _ := appStore.ListTenantDTrackSources(ctx, tn.ID); len(st) != 1 || !st[0].WebhookEnabled || !st[0].TrustDecisions {
		t.Fatalf("status: %+v", st)
	}

	// A hand mapping survives the next sync, which finds no rule for the project.
	app := &domain.Application{ID: uuid.New(), TenantID: tn.ID, Slug: "payments", Name: "payments"}
	if err := appStore.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	rec := domain.DTrackProjectRecord{TenantID: tn.ID, SourceID: srcID, ProjectUUID: "p-1", Name: "payments-api", Active: true, UnmappedReason: "no rule"}
	if err := appStore.UpsertDTrackProject(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := appStore.MapDTrackProject(ctx, tn.ID, "p-1", app.ID); err != nil {
		t.Fatal(err)
	}
	if err := appStore.UpsertDTrackProject(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if un, _ := appStore.ListUnmappedDTrackProjects(ctx, tn.ID, srcID); len(un) != 0 {
		t.Fatalf("the hand mapping was overwritten by the sync: %+v", un)
	}
	if a, err := appStore.FindAssetByDTrackUUID(ctx, tn.ID, "p-1"); err != nil || a.ApplicationID == nil || *a.ApplicationID != app.ID {
		t.Fatalf("mapping rule 3 reads the hand mapping: %+v %v", a, err)
	}

	// A decision is new once; the same decision again is not; a different one is.
	seedFindings(t, ctx, appStore, tn.ID, 1)
	fs, _ := appStore.ListFindings(ctx, tn.ID)
	if len(fs) == 0 {
		t.Fatal("no finding seeded")
	}
	d := store.DTrackDecision{FindingID: fs[0].ID, SourceID: srcID, State: "not_affected", Justification: "code_not_reachable"}
	if changed, err := appStore.RecordDTrackDecision(ctx, tn.ID, d); err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	if changed, _ := appStore.RecordDTrackDecision(ctx, tn.ID, d); changed {
		t.Fatal("the same decision again is not new")
	}
	d.State = "affected"
	if changed, _ := appStore.RecordDTrackDecision(ctx, tn.ID, d); !changed {
		t.Fatal("a changed decision is new")
	}
	if p, _ := appStore.ListDTrackDecisions(ctx, tn.ID, srcID, true); len(p) != 1 {
		t.Fatalf("one pending decision: %d", len(p))
	}

	// Debounce: a running sync turns a second event into a trailing pass; a sync stuck for over an hour is idle.
	if start, _ := appStore.EnqueueDTrackSync(ctx, tn.ID, srcID, "p-1"); !start {
		t.Fatal("first event starts a sync")
	}
	if start, _ := appStore.EnqueueDTrackSync(ctx, tn.ID, srcID, "p-1"); start {
		t.Fatal("a second event while running only marks it dirty")
	}
	conn, err := sys.Pool().Exec(ctx, `UPDATE dtrack_sync SET updated_at = NOW() - interval '2 hours' WHERE tenant_id = $1`, tn.ID)
	if err != nil || conn.RowsAffected() != 1 {
		t.Fatalf("aging the row: %v", err)
	}
	if start, _ := appStore.EnqueueDTrackSync(ctx, tn.ID, srcID, "p-1"); !start {
		t.Fatal("a sync stuck for two hours is taken as idle, so the project is not blocked for ever")
	}
}
