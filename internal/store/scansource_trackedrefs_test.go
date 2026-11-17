package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// spec.trackedRefs is stored with the source's policy. Removing it from the resource must remove it: SaveScanSource kept
// the old policy whenever the new one was empty, so a list could be added but never taken away.
func TestScanSourceTrackedRefs_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "tr-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}

	id, err := appStore.SaveScanSource(ctx, tn.ID, "ci", "semgrep", domain.WithTrackedRefs(&domain.IngestionPolicy{MinimumSeverity: "low"}, []string{"develop", "release/*"}))
	if err != nil {
		t.Fatal(err)
	}
	p, err := appStore.GetScanSourceIngestionPolicy(ctx, tn.ID, id)
	if err != nil || p == nil || len(p.TrackedRefs) != 2 || p.TrackedRefs[0] != "develop" || p.MinimumSeverity != "low" {
		t.Fatalf("stored with the policy: %+v %v", p, err)
	}

	// The list changes.
	if _, err := appStore.SaveScanSource(ctx, tn.ID, "ci", "semgrep", domain.WithTrackedRefs(&domain.IngestionPolicy{MinimumSeverity: "low"}, []string{"staging"})); err != nil {
		t.Fatal(err)
	}
	if p, _ := appStore.GetScanSourceIngestionPolicy(ctx, tn.ID, id); p == nil || len(p.TrackedRefs) != 1 || p.TrackedRefs[0] != "staging" {
		t.Fatalf("a changed list replaces the old one: %+v", p)
	}

	// The list is removed from the resource: the defaults come back.
	if id2, err := appStore.SaveScanSource(ctx, tn.ID, "ci", "semgrep", nil); err != nil || id2 != id {
		t.Fatalf("the same source: %v %v", id2, err)
	}
	if p, _ := appStore.GetScanSourceIngestionPolicy(ctx, tn.ID, id); p != nil && len(p.TrackedRefs) != 0 {
		t.Fatalf("a resource with no trackedRefs and no policy must not keep the old list: %+v", p)
	}
}
