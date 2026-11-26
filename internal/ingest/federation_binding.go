package ingest

import (
	"errors"
	"fmt"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// A federated ingest token is bound to the CI run that exchanged it (D80). The binding travels in the token's
// scopes, so every replica and both upload paths read it the same way.
const (
	bindRepoPrefix = "bind:repo:"
	bindRefPrefix  = "bind:ref:"
	bindShaPrefix  = "bind:sha:"
)

// ErrContextMismatch is returned when an upload states a repository, branch or commit other than the one the
// federated token was issued for.
var ErrContextMismatch = errors.New("upload context does not match the CI token")

// federationBindings derives the binding scopes from the verified claims of the token a rule matched: the provider's own claims
// for GitHub and GitLab, or the claims the rule names (RepositoryClaim, RefClaim) for any other issuer (docs/51 step 1.3).
func federationBindings(rule domain.TrustRule, issuer string, claims map[string]any) []string {
	var out []string
	switch rule.Provider {
	case "github":
		if repo := claimStr(claims, "repository"); repo != "" {
			if server := githubServer(issuer); server != "" {
				out = append(out, bindRepoPrefix+server+"/"+repo)
			} else {
				out = append(out, bindRepoPrefix+repo) // host unknown: bound by owner/repo only
			}
		}
		if ref := claimStr(claims, "ref"); ref != "" {
			out = append(out, bindRefPrefix+ref)
		}
	case "gitlab":
		if p := claimStr(claims, "project_path"); p != "" {
			out = append(out, bindRepoPrefix+strings.TrimSuffix(issuer, "/")+"/"+p)
		}
		if ref := claimStr(claims, "ref"); ref != "" {
			if claimStr(claims, "ref_type") == "tag" {
				ref = "refs/tags/" + ref
			}
			out = append(out, bindRefPrefix+ref)
		}
	default:
		if c := strings.TrimSpace(rule.RepositoryClaim); c != "" {
			if repo := claimStr(claims, c); repo != "" {
				out = append(out, bindRepoPrefix+repo)
			}
		}
		if c := strings.TrimSpace(rule.RefClaim); c != "" {
			if ref := claimStr(claims, c); ref != "" {
				out = append(out, bindRefPrefix+ref)
			}
		}
	}
	if sha := claimStr(claims, "sha"); sha != "" {
		out = append(out, bindShaPrefix+strings.ToLower(sha))
	}
	return out
}

// githubServer is the web address of the GitHub that issued the token: github.com for the public issuer, the
// enterprise host for GitHub Enterprise Server (issuer https://HOST/_services/token), and "" when the issuer has
// neither form, in which case the repository is bound by its owner/repo path alone.
func githubServer(issuer string) string {
	iss := strings.TrimSuffix(issuer, "/")
	if iss == "https://token.actions.githubusercontent.com" {
		return "https://github.com"
	}
	if strings.HasSuffix(iss, "/_services/token") {
		return strings.TrimSuffix(iss, "/_services/token")
	}
	return ""
}

// sameRepository compares a stated repository with the bound one. A bound value with a host compares host and
// path; a bound owner/repo path compares the path only.
func sameRepository(stated, bound string) bool {
	s, b := normalize.RepositoryURL(stated), normalize.RepositoryURL(bound)
	if strings.Contains(b, "://") {
		return s == b
	}
	return repoPath(s) == strings.Trim(b, "/")
}

// repoPath is the owner/repo part of a normalized repository key.
func repoPath(key string) string {
	if i := strings.Index(key, "://"); i >= 0 {
		rest := key[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return strings.Trim(rest[j:], "/")
		}
		return ""
	}
	return strings.Trim(key, "/")
}

// BindUploadContext applies a federated token's binding to an upload's context (D80). A field the client left
// empty is filled from the token; a field it filled must agree with the token, or the upload is refused. Without
// this a run on a feature branch could state branch=main and close main's findings (closing depends on the
// branch being a tracked ref, D10, D22). Tokens without bindings (personal and API tokens) are left alone.
func BindUploadContext(scopes []string, ctx *domain.UploadContext) error {
	for _, sc := range scopes {
		switch {
		case strings.HasPrefix(sc, bindRepoPrefix):
			bound := strings.TrimPrefix(sc, bindRepoPrefix)
			if ctx.Repository == "" {
				ctx.Repository = bound
			} else if !sameRepository(ctx.Repository, bound) {
				return fmt.Errorf("%w: repository %q, the token is for %q", ErrContextMismatch, ctx.Repository, bound)
			}
		case strings.HasPrefix(sc, bindRefPrefix):
			bound := branchOfRef(strings.TrimPrefix(sc, bindRefPrefix))
			if ctx.Branch == "" {
				ctx.Branch = bound
			} else if branchOfRef(ctx.Branch) != bound {
				return fmt.Errorf("%w: branch %q, the token is for %q", ErrContextMismatch, ctx.Branch, bound)
			}
		case strings.HasPrefix(sc, bindShaPrefix):
			bound := strings.TrimPrefix(sc, bindShaPrefix)
			c := strings.ToLower(strings.TrimSpace(ctx.Commit))
			switch {
			case c == "":
				ctx.Commit = bound
			case c == bound, len(c) >= 7 && strings.HasPrefix(bound, c): // an abbreviated sha of the same commit
				ctx.Commit = bound
			default:
				return fmt.Errorf("%w: commit %q, the token is for %q", ErrContextMismatch, ctx.Commit, bound)
			}
		}
	}
	return nil
}

// branchOfRef turns refs/heads/main into main; pull-request and tag refs are kept whole, so they stay ephemeral
// or distinct (D10).
func branchOfRef(ref string) string {
	return strings.TrimPrefix(strings.TrimSpace(ref), "refs/heads/")
}

// TokenOptions reads the tightening options a token carries (D22): min_sev:<severity> and no_close. The direct
// path applies them at once; the presigned path stores them on the upload for the parse worker (D80).
func TokenOptions(scopes []string) domain.UploadOptions {
	var o domain.UploadOptions
	for _, sc := range scopes {
		switch {
		case sc == "no_close":
			o.NoClose = true
		case strings.HasPrefix(sc, "min_sev:"):
			if sev := domain.ParseSeverity(strings.TrimPrefix(sc, "min_sev:")); sev.Valid() {
				o.MinSeverity = sev
			}
		}
	}
	return o
}
