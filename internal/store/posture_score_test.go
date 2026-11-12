package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	ingestpkg "rampart/internal/ingest"
)

// The posture score normalizes weighted open risk by the application's own asset count (docs/06 section 2,
// D62): two applications with the same single open critical finding must not read the same posture when one
// has far more assets than the other, because spreading the same absolute risk over more assets is a better
// outcome, not a neutral one. Before D62 every call site passed 1 (or the application count), so the asset
// column had no effect at all; this is the regression guard.
func TestPostureScoreNormalizesByAssetCount(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)

	makeApp := func(slug string, extraAssets int) {
		app := &domain.Application{ID: uuid.New(), TenantID: h.tenant, Slug: slug, Name: slug, BusinessCriticality: "high", Lifecycle: "production", CreatedAt: time.Now().UTC()}
		if err := h.store.CreateApplication(ctx, app); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		for i := 0; i < extraAssets; i++ {
			if err := h.store.CreateAsset(ctx, &domain.Asset{
				ID: uuid.New(), TenantID: h.tenant, ApplicationID: &app.ID, Type: domain.AssetHost,
				Key: slug + "-extra-" + uuid.NewString(), DisplayName: slug, Active: true, FirstSeen: now, LastSeen: now,
			}); err != nil {
				t.Fatal(err)
			}
		}
		repo := domain.UploadContext{Repository: "github.com/acme/" + slug, Branch: "main"}
		// Pre-create the asset the scan will resolve to, bound to this application: D10 step (a) keeps a
		// finding under an asset's existing application, so without this the scan would land in Unassigned.
		if err := h.store.CreateAsset(ctx, &domain.Asset{
			ID: uuid.New(), TenantID: h.tenant, ApplicationID: &app.ID, Type: domain.AssetRepository,
			Key: ingestpkg.DeriveAssetKey(domain.AssetRepository, repo), DisplayName: slug, Active: true, FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatal(err)
		}
		h.formatHint = ""
		run := h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.crit", "a.go", 3)), repo))
		if run.Status != domain.RunCompleted {
			t.Fatalf("%s: ingest %s %s", slug, run.Status, run.Error)
		}
		list, err := h.app.ListFindings(ctx, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range list {
			if f.ApplicationID == app.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: the scanned finding did not land under its own application", slug)
		}
	}

	makeApp("few-assets", 0)  // 1 asset in total (the scanned repository)
	makeApp("many-assets", 9) // 10 assets in total (the repository plus 9 more)

	summaries, err := h.store.ApplicationSummaries(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var few, many *domain.AppSummary
	for i := range summaries {
		switch summaries[i].Slug {
		case "few-assets":
			few = &summaries[i]
		case "many-assets":
			many = &summaries[i]
		}
	}
	if few == nil || many == nil {
		t.Fatalf("both applications must be listed: %+v", summaries)
	}
	if few.AssetCount != 1 {
		t.Fatalf("few-assets: AssetCount %d, want 1", few.AssetCount)
	}
	if many.AssetCount != 10 {
		t.Fatalf("many-assets: AssetCount %d, want 10", many.AssetCount)
	}
	if few.PostureScore >= 1000 || many.PostureScore >= 1000 {
		t.Fatalf("both applications have an open finding, so neither should read a clean 1000: few=%d many=%d", few.PostureScore, many.PostureScore)
	}
	if few.PostureScore >= many.PostureScore {
		t.Fatalf("the same absolute risk spread over more assets must score a better posture: few=%d (1 asset) many=%d (10 assets)",
			few.PostureScore, many.PostureScore)
	}
}
