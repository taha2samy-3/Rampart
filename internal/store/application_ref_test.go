package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/domain"
)

// docs/51 step 2.5 on PostgreSQL: a ScanSource's applicationRef by repository matches the suffix .git, not the characters of it,
// and a repository with an application per branch (D140) is ambiguous instead of whichever row came first.
func TestFindApplicationByRef_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "ref-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	save := func(slug, repo, branch string) {
		if err := appStore.SaveApplication(ctx, domain.Application{ID: domain.NewID(), TenantID: tn.ID, Slug: slug, Name: slug, Type: "repo",
			Repository: repo, Branch: branch, Version: 1, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	save("rampart-main", "https://github.com/acme/rampart.git", "main")
	save("shop-main", "https://github.com/acme/shop", "main")
	save("shop-release", "https://github.com/acme/shop", "release")

	app, err := appStore.FindApplicationByRef(ctx, tn.ID, domain.ApplicationRef{Repository: "https://github.com/acme/rampart"})
	if err != nil || app == nil || app.Slug != "rampart-main" {
		t.Fatalf("a repository whose name ends in t is found (rtrim stripped it to rampar): %+v %v", app, err)
	}
	if app, err := appStore.FindApplicationByRef(ctx, tn.ID, domain.ApplicationRef{Repository: "https://github.com/acme/rampar"}); err != nil || app != nil {
		t.Fatalf("a shorter name must not match: %+v %v", app, err)
	}
	if _, err := appStore.FindApplicationByRef(ctx, tn.ID, domain.ApplicationRef{Repository: "https://github.com/acme/shop.git"}); !errors.Is(err, domain.ErrAmbiguousApplicationRef) {
		t.Fatalf("two branch applications of one repository are ambiguous, got %v", err)
	}
}
