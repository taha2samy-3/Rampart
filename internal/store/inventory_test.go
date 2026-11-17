package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// The inventory page asked for /api/v1/inventory and /inventory/components, which did not exist: an SBOM that
// was uploaded and parsed never showed. The assets with their open findings, and the packages of the latest
// SBOM of each asset, from the database, per tenant.
func TestInventory_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	mk := func() *domain.Tenant {
		tn := &domain.Tenant{ID: uuid.New(), Slug: "inv-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
		if err := sys.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
		return tn
	}
	tn, other := mk(), mk()
	seedFindings(t, ctx, appStore, tn.ID, 8)
	seedFindings(t, ctx, appStore, other.ID, 4) // another tenant's assets must never show
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")

	// An SBOM, then a newer one: only the latest counts.
	run := &domain.IngestRun{ID: uuid.New(), TenantID: tn.ID, ApplicationID: app.ID, AssetID: asset.ID, Track: "default", ScannerFamily: "cyclonedx",
		Format: "cyclonedx", Status: domain.RunCompleted, CreatedAt: time.Now().UTC()}
	if err := appStore.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	save := func(age time.Duration, comps ...domain.SBOMComponent) {
		id := uuid.New()
		for i := range comps {
			comps[i].TenantID, comps[i].SBOMID = tn.ID, id
		}
		if err := appStore.SaveSBOM(ctx, &domain.SBOM{ID: id, TenantID: tn.ID, AssetID: asset.ID, IngestRunID: run.ID, Format: "cyclonedx", SpecVersion: "1.5",
			ComponentCount: len(comps), CreatedAt: time.Now().UTC().Add(-age)}, comps); err != nil {
			t.Fatal(err)
		}
	}
	save(48*time.Hour, domain.SBOMComponent{Ref: "old", Purl: "pkg:npm/left-pad@1.0.0", PurlBase: "pkg:npm/left-pad", Name: "left-pad", Version: "1.0.0"})
	save(0,
		domain.SBOMComponent{Ref: "a", Purl: "pkg:npm/lodash@4.17.20", PurlBase: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20", Licenses: []string{"MIT"}, Direct: true},
		domain.SBOMComponent{Ref: "b", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", PurlBase: "pkg:maven/org.apache.logging.log4j/log4j-core", Name: "log4j-core", Version: "2.14.1"},
	)

	var r store.InventoryReader = appStore
	assets, err := r.ListInventoryAssets(ctx, tn.ID, 100)
	if err != nil || len(assets) != 1 {
		t.Fatalf("assets: %d %v", len(assets), err)
	}
	a := assets[0]
	if a.ID != asset.ID || a.Name != "shop" || a.Kind != "repository" || a.Application != "Shop" || a.Components != 2 || a.Total == 0 || a.Total < a.Critical+a.High {
		t.Errorf("asset row: %+v", a)
	}

	comps, total, err := r.ListInventoryComponents(ctx, tn.ID, "", 100)
	if err != nil || total != 2 || len(comps) != 2 {
		t.Fatalf("components: %d of %d %v (the old SBOM must not count)", len(comps), total, err)
	}
	byName := map[string]store.InventoryComponent{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if c := byName["lodash"]; c.Type != "npm" || c.License != "MIT" || !c.Direct || c.Asset != "shop" || c.Application != "Shop" {
		t.Errorf("lodash: %+v", c)
	}
	if byName["log4j-core"].Type != "maven" {
		t.Errorf("log4j-core: %+v", byName["log4j-core"])
	}

	// Search matches the name, the purl and the version, and % and _ are not wildcards.
	for q, want := range map[string]int{"LODASH": 1, "maven": 1, "2.14": 1, "nothing": 0, "%": 0, "_": 0, "pkg:npm": 1} {
		got, tot, err := r.ListInventoryComponents(ctx, tn.ID, q, 100)
		if err != nil || len(got) != want || tot != want {
			t.Errorf("search %q: %d of %d (want %d) %v", q, len(got), tot, want, err)
		}
	}
	if got, tot, _ := r.ListInventoryComponents(ctx, tn.ID, "", 1); len(got) != 1 || tot != 2 {
		t.Errorf("a limit cuts the rows, not the total: %d of %d", len(got), tot)
	}

	// Another tenant sees none of this.
	oa, _ := r.ListInventoryAssets(ctx, other.ID, 100)
	oc, _, _ := r.ListInventoryComponents(ctx, other.ID, "", 100)
	if len(oa) != 1 || oa[0].ID == asset.ID || len(oc) != 0 {
		t.Errorf("tenant isolation: %d assets, %d components", len(oa), len(oc))
	}
}

// An SBOM belongs to a track of an asset: the same repository built from main, staging and a release branch has
// three SBOMs. With one slot per asset the last upload replaced the others and the inventory showed whichever
// branch ran last.
func TestInventory_OneSBOMPerTrack_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "trk-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	run := &domain.IngestRun{ID: uuid.New(), TenantID: tn.ID, ApplicationID: app.ID, AssetID: asset.ID, Track: "main", ScannerFamily: "cyclonedx",
		Format: "cyclonedx", Status: domain.RunCompleted, CreatedAt: time.Now().UTC()}
	if err := appStore.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	save := func(track string, age time.Duration, pkg string) {
		id := uuid.New()
		c := domain.SBOMComponent{TenantID: tn.ID, SBOMID: id, Ref: pkg, Purl: "pkg:npm/" + pkg + "@1.0.0", PurlBase: "pkg:npm/" + pkg, Name: pkg, Version: "1.0.0"}
		if err := appStore.SaveSBOM(ctx, &domain.SBOM{ID: id, TenantID: tn.ID, AssetID: asset.ID, IngestRunID: run.ID, Track: track, Format: "cyclonedx", SpecVersion: "1.5",
			ComponentCount: 1, CreatedAt: time.Now().UTC().Add(-age)}, []domain.SBOMComponent{c}); err != nil {
			t.Fatal(err)
		}
	}
	save("main", 3*time.Hour, "on-main")
	save("staging", 2*time.Hour, "on-staging")
	save("release-2", 0, "on-release")  // the newest upload of the asset, from a branch that is not the primary one
	save("staging", 0, "on-staging-v2") // a newer SBOM of staging replaces the older one of staging, not the others

	comps, total, err := appStore.ListInventoryComponents(ctx, tn.ID, "", 100)
	if err != nil || total != 3 || len(comps) != 3 {
		t.Fatalf("one SBOM per track, the newest of each: %d of %d %v", len(comps), total, err)
	}
	byTrack := map[string]string{}
	for _, c := range comps {
		byTrack[c.Track] = c.Name
	}
	if byTrack["main"] != "on-main" || byTrack["staging"] != "on-staging-v2" || byTrack["release-2"] != "on-release" {
		t.Errorf("each track keeps its own SBOM: %v", byTrack)
	}
	assets, _ := appStore.ListInventoryAssets(ctx, tn.ID, 10)
	if len(assets) != 1 || assets[0].Components != 1 {
		t.Errorf("the asset row counts components of one SBOM, not of all tracks added: %+v", assets)
	}

	// The asset's single SBOM (the SBOM export, the graph) is the primary track's, not the last upload's.
	sbom, comps2, err := appStore.GetSBOM(ctx, tn.ID, asset.ID)
	if err != nil || sbom.Track != "main" || len(comps2) != 1 || comps2[0].Name != "on-main" {
		t.Fatalf("GetSBOM must prefer main over the newest upload: %+v %v", sbom, err)
	}
}
