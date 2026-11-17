package ingest_test

import (
	"context"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func TestDetermineAssetType(t *testing.T) {
	tests := []struct {
		category domain.FindingCategory
		ctx      domain.UploadContext
		want     domain.AssetType
	}{
		{domain.CategorySAST, domain.UploadContext{Repository: "https://github.com/acme/app"}, domain.AssetRepository},
		{domain.CategorySecret, domain.UploadContext{Repository: "https://github.com/acme/app"}, domain.AssetRepository},
		{domain.CategorySCA, domain.UploadContext{ImageRef: "docker.io/library/nginx:latest"}, domain.AssetImage},
		{domain.CategorySCA, domain.UploadContext{Repository: "https://github.com/acme/app"}, domain.AssetRepository},
		{domain.CategoryContainer, domain.UploadContext{ImageRef: "docker.io/library/nginx:latest"}, domain.AssetImage},
		{domain.CategoryDAST, domain.UploadContext{Repository: "https://example.com/api"}, domain.AssetURL},
	}

	for _, tt := range tests {
		got := ingest.DetermineAssetType(tt.category, tt.ctx)
		if got != tt.want {
			t.Errorf("DetermineAssetType(%s) = %s, want %s", tt.category, got, tt.want)
		}
	}
}

func TestNormalizeRepositoryURL(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://github.com/Acme/Repo.git", "https://github.com/acme/repo"},
		{"git@github.com:Acme/Repo.git", "https://github.com/acme/repo"},
		{"https://gitlab.com/group/subgroup/project.git/", "https://gitlab.com/group/subgroup/project"},
		{"acme/repo", "acme/repo"},
	}

	for _, c := range cases {
		got := ingest.NormalizeRepositoryURL(c.input)
		if got != c.want {
			t.Errorf("NormalizeRepositoryURL(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestNormalizeImageRef(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"docker.io/library/nginx:latest", "docker.io/library/nginx"},
		{"ghcr.io/acme/api:v1.2.3@sha256:abcdef", "ghcr.io/acme/api"},
		{"localhost:5000/my-image:1.0", "localhost:5000/my-image"},
		{"ubuntu:22.04", "ubuntu"},
	}

	for _, c := range cases {
		got := ingest.NormalizeImageRef(c.input)
		if got != c.want {
			t.Errorf("NormalizeImageRef(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestResolveAssetAndApplication(t *testing.T) {
	store := ingest.NewMemoryStore()
	tenantID := domain.NewID()
	ctx := context.Background()

	// 1. Resolve new asset
	asset1, err := ingest.ResolveAsset(ctx, store, tenantID, domain.AssetRepository, "https://github.com/acme/backend")
	if err != nil {
		t.Fatalf("unexpected error resolving asset: %v", err)
	}
	if asset1.Key != "https://github.com/acme/backend" {
		t.Errorf("unexpected asset key: %s", asset1.Key)
	}

	// 2. Rescan resolves the exact same asset ID (D10, D11 deduplication fix)
	asset2, err := ingest.ResolveAsset(ctx, store, tenantID, domain.AssetRepository, "https://github.com/acme/backend")
	if err != nil {
		t.Fatalf("unexpected error re-resolving asset: %v", err)
	}
	if asset1.ID != asset2.ID {
		t.Errorf("asset ID mismatch on rescan! Got %s vs %s (dedup broken)", asset1.ID, asset2.ID)
	}

	// 3. Resolve Application default "unassigned"
	appID, err := ingest.ResolveApplication(ctx, store, tenantID, asset1, "")
	if err != nil {
		t.Fatalf("unexpected error resolving application: %v", err)
	}
	if appID == domain.NilID {
		t.Fatal("expected non-nil application id")
	}

	// Check that unassigned application was created and bound
	app, err := store.LookupApplication(ctx, tenantID, "unassigned")
	if err != nil {
		t.Fatalf("expected unassigned application in store: %v", err)
	}
	if app.ID != appID {
		t.Errorf("expected app id %s, got %s", appID, app.ID)
	}
}

func TestIsEphemeral(t *testing.T) {
	tracked := []string{"main", "master", "release/*"}

	if !ingest.IsEphemeral("refs/pull/42/merge", tracked) {
		t.Error("expected refs/pull/42/merge to be ephemeral")
	}
	if !ingest.IsEphemeral("pr/feature-x", tracked) {
		t.Error("expected pr/feature-x to be ephemeral")
	}
	if !ingest.IsEphemeral("feature/login", tracked) {
		t.Error("expected untracked feature/login to be ephemeral")
	}
	if ingest.IsEphemeral("main", tracked) {
		t.Error("expected main branch to NOT be ephemeral")
	}
	if ingest.IsEphemeral("release/1.0", tracked) {
		t.Error("expected release/1.0 branch to NOT be ephemeral")
	}
}

// The branches a ScanSource tracks (spec.trackedRefs): an exact name, a trailing * as a prefix, * for all. A pull
// request stays ephemeral whatever the list says.
func TestIsEphemeral_TrackedRefsOfASource(t *testing.T) {
	cases := []struct {
		name   string
		refs   []string
		branch string
		want   bool
	}{
		{"no list: develop is ephemeral (the defaults do not include it)", nil, "develop", true},
		{"no list: main is tracked", nil, "main", false},
		{"no list: release/1.0 is tracked", nil, "release/1.0", false},
		{"listed exactly", []string{"develop", "staging"}, "develop", false},
		{"another listed one", []string{"develop", "staging"}, "staging", false},
		{"listing develop does not track main: the list replaces the defaults", []string{"develop"}, "main", true},
		{"a prefix", []string{"hotfix-*"}, "hotfix-2026-11", false},
		{"a prefix is not a substring", []string{"hotfix-*"}, "my-hotfix-2026", true},
		{"a path prefix", []string{"release/*"}, "release/2.1", false},
		{"a path prefix does not match the bare word", []string{"release/*"}, "release", true},
		{"every ref", []string{"*"}, "feature/anything", false},
		{"every ref, but a pull request is still ephemeral", []string{"*"}, "refs/pull/42/merge", true},
		{"pr/ is ephemeral too", []string{"*"}, "pr/42", true},
		{"merge-requests/ is ephemeral too", []string{"*"}, "merge-requests/7/head", true},
		{"no branch at all is tracked (the environment is the track)", []string{"main"}, "", false},
		{"the match is case-sensitive, as a branch name is", []string{"main"}, "Main", true},
	}
	for _, c := range cases {
		if got := ingest.IsEphemeral(c.branch, c.refs); got != c.want {
			t.Errorf("%s: IsEphemeral(%q, %v) = %v, want %v", c.name, c.branch, c.refs, got, c.want)
		}
	}
}
