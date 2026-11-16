package ingest

import (
	"errors"
	"testing"

	"rampart/internal/domain"
)

func TestFederationBindings(t *testing.T) {
	gh := federationBindings("github", "https://token.actions.githubusercontent.com",
		map[string]any{"repository": "acme/shop", "ref": "refs/pull/7/merge", "sha": "ABCDEF1234567"})
	want := []string{"bind:repo:https://github.com/acme/shop", "bind:ref:refs/pull/7/merge", "bind:sha:abcdef1234567"}
	if len(gh) != len(want) {
		t.Fatalf("github bindings: %v", gh)
	}
	for i := range want {
		if gh[i] != want[i] {
			t.Errorf("github binding %d: %q, want %q", i, gh[i], want[i])
		}
	}
	ghes := federationBindings("github", "https://git.corp.example/_services/token", map[string]any{"repository": "a/b"})
	if ghes[0] != "bind:repo:https://git.corp.example/a/b" {
		t.Errorf("GitHub Enterprise Server: %v", ghes)
	}
	other := federationBindings("github", "https://idp.test", map[string]any{"repository": "a/b"})
	if other[0] != "bind:repo:a/b" {
		t.Errorf("unknown issuer host: bound by path only: %v", other)
	}
	if !sameRepository("https://github.com/A/b.git", "a/b") || sameRepository("https://github.com/a/c", "a/b") {
		t.Error("path-only binding compares owner/repo")
	}
	gl := federationBindings("gitlab", "https://gitlab.example.com/", map[string]any{"project_path": "grp/app", "ref": "v1.2", "ref_type": "tag"})
	if gl[0] != "bind:repo:https://gitlab.example.com/grp/app" || gl[1] != "bind:ref:refs/tags/v1.2" {
		t.Errorf("gitlab bindings: %v", gl)
	}
}

func TestBindUploadContext(t *testing.T) {
	scopes := []string{"ingest", "bind:repo:https://github.com/acme/shop", "bind:ref:refs/pull/7/merge", "bind:sha:abcdef1234567890"}

	// A pull-request run stays a pull-request run: its ref is kept whole, so it is ephemeral (D10).
	var c domain.UploadContext
	if err := BindUploadContext(scopes, &c); err != nil {
		t.Fatal(err)
	}
	if c.Branch != "refs/pull/7/merge" || c.Repository != "https://github.com/acme/shop" || c.Commit != "abcdef1234567890" {
		t.Fatalf("filled context: %+v", c)
	}
	for name, ctx := range map[string]domain.UploadContext{
		"main instead of the PR": {Branch: "main"},
		"other repository":       {Repository: "https://github.com/acme/other"},
		"other host":             {Repository: "https://gitlab.com/acme/shop"},
		"short other sha":        {Commit: "abcdef0"},
		"too short a prefix":     {Commit: "abcdef"},
	} {
		if err := BindUploadContext(scopes, &ctx); !errors.Is(err, ErrContextMismatch) {
			t.Errorf("%s: want a mismatch, got %v", name, err)
		}
	}

	// A token with no binding (personal or API token) changes nothing.
	plain := domain.UploadContext{Branch: "main"}
	if err := BindUploadContext([]string{"ingest", "read"}, &plain); err != nil || plain.Branch != "main" {
		t.Fatalf("unbound token: %v %+v", err, plain)
	}
}
