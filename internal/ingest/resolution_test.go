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
