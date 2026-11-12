package normalize

import (
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func TestMatchApplication(t *testing.T) {
	org, shop, tools, img := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	apps := []AppSelectors{
		{ID: org, Slug: "acme-all", Selectors: domain.Selectors{Repositories: []domain.RepositorySelector{{URL: "https://github.com/acme/*"}}}},
		{ID: shop, Slug: "shop", Selectors: domain.Selectors{Repositories: []domain.RepositorySelector{{URL: "git@github.com:Acme/Shop.git"}}}},
		{ID: tools, Slug: "tools", Selectors: domain.Selectors{Repositories: []domain.RepositorySelector{{URL: "https://github.com/acme/tools-*"}}}},
		{ID: img, Slug: "api", Selectors: domain.Selectors{Images: []domain.ImageSelector{{Repository: "Registry.acme.example/shop/api:2.14.0"}}}},
	}
	cases := []struct {
		typ  domain.AssetType
		key  string
		want uuid.UUID
		ok   bool
	}{
		{domain.AssetRepository, "https://github.com/acme/shop", shop, true},       // exact (scp form, case folded) beats the org prefix
		{domain.AssetRepository, "https://github.com/acme/tools-cli", tools, true}, // the longer prefix wins
		{domain.AssetRepository, "https://github.com/acme/billing", org, true},
		{domain.AssetRepository, "https://github.com/acme-labs/x", uuid.Nil, false}, // "acme/*" does not claim "acme-labs"
		{domain.AssetImage, "registry.acme.example/shop/api", img, true},            // the tag in the pattern is ignored
		{domain.AssetImage, "https://github.com/acme/shop", uuid.Nil, false},        // repository selectors do not match images
	}
	for _, c := range cases {
		got, ok := MatchApplication(apps, c.typ, c.key)
		if ok != c.ok || got != c.want {
			t.Fatalf("%s %s: %v %v", c.typ, c.key, got, ok)
		}
	}
	// Two applications with the same pattern: the smaller slug, whatever the order.
	a, b := uuid.New(), uuid.New()
	same := domain.Selectors{Repositories: []domain.RepositorySelector{{URL: "https://github.com/x/y"}}}
	for _, order := range [][]AppSelectors{{{ID: b, Slug: "beta", Selectors: same}, {ID: a, Slug: "alpha", Selectors: same}}, {{ID: a, Slug: "alpha", Selectors: same}, {ID: b, Slug: "beta", Selectors: same}}} {
		if got, _ := MatchApplication(order, domain.AssetRepository, "https://github.com/x/y"); got != a {
			t.Fatal("a tie must go to the smaller slug")
		}
	}
}
