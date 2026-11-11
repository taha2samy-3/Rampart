package ingest

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/store"
)

// DetermineAssetType derives the primary asset type per normative D10.
func DetermineAssetType(category domain.FindingCategory, uctx domain.UploadContext) domain.AssetType {
	switch category {
	case domain.CategorySAST, domain.CategorySecret, domain.CategoryIaC, domain.CategoryLicense:
		return domain.AssetRepository
	case domain.CategorySCA:
		if uctx.ImageDigest != "" || uctx.ImageRef != "" {
			return domain.AssetImage
		}
		return domain.AssetRepository
	case domain.CategoryContainer:
		return domain.AssetImage
	case domain.CategoryDAST:
		return domain.AssetURL
	case domain.CategoryCSPM:
		return domain.AssetCloudResource
	default:
		if uctx.ImageRef != "" {
			return domain.AssetImage
		}
		if uctx.Repository != "" {
			return domain.AssetRepository
		}
		return domain.AssetRepository
	}
}

// DeriveAssetKey extracts the normative natural key for an asset (D10).
// An asset is the long-lived entity; versions are builds/commits of it.
func DeriveAssetKey(assetType domain.AssetType, uctx domain.UploadContext) string {
	switch assetType {
	case domain.AssetRepository:
		repo := strings.TrimSpace(uctx.Repository)
		if repo == "" {
			repo = "default-repository"
		}
		return NormalizeRepositoryURL(repo)

	case domain.AssetImage:
		ref := strings.TrimSpace(uctx.ImageRef)
		if ref == "" {
			ref = strings.TrimSpace(uctx.Repository)
		}
		if ref == "" {
			ref = "default-image"
		}
		return NormalizeImageRef(ref)

	case domain.AssetURL:
		rawURL := strings.TrimSpace(uctx.Repository)
		if rawURL == "" {
			rawURL = "http://localhost"
		}
		return normalize.NormalizeURL(rawURL)

	case domain.AssetWorkload:
		svc := strings.TrimSpace(uctx.Service)
		if svc == "" {
			svc = "default-workload"
		}
		return svc

	default:
		if uctx.Repository != "" {
			return NormalizeRepositoryURL(uctx.Repository)
		}
		return "default-asset"
	}
}

// NormalizeRepositoryURL normalizes a Git repository URL (stripping credentials, trailing .git, and lowercasing host).
func NormalizeRepositoryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "/")
	// Handle scp-like syntax: git@github.com:org/repo.git
	if strings.HasPrefix(raw, "git@") {
		parts := strings.SplitN(raw[4:], ":", 2)
		if len(parts) == 2 {
			host := strings.ToLower(parts[0])
			repoPath := strings.TrimSuffix(strings.TrimSuffix(parts[1], "/"), ".git")
			repoPath = strings.TrimPrefix(repoPath, "/")
			return "https://" + host + "/" + strings.ToLower(repoPath)
		}
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Treat as plain path or slug
		clean := strings.TrimSuffix(strings.TrimPrefix(raw, "/"), ".git")
		return strings.ToLower(clean)
	}

	host := strings.ToLower(u.Host)
	cleanPath := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	cleanPath = path.Clean(cleanPath)
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	} else if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}

	return scheme + "://" + host + strings.ToLower(cleanPath)
}

// NormalizeImageRef strips tags and digests from container image references per D10 (registry/repository).
func NormalizeImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	// Strip digest (@sha256:...)
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Strip tag (:latest, :v1.0), accounting for registry port (e.g. localhost:5000/repo:tag)
	lastSlash := strings.LastIndex(ref, "/")
	if lastSlash != -1 {
		repoPart := ref[lastSlash+1:]
		if colonIdx := strings.Index(repoPart, ":"); colonIdx != -1 {
			ref = ref[:lastSlash+1] + repoPart[:colonIdx]
		}
	} else {
		if colonIdx := strings.Index(ref, ":"); colonIdx != -1 {
			ref = ref[:colonIdx]
		}
	}

	return strings.ToLower(ref)
}

// ResolveAsset resolves or creates the long-lived asset matching (tenant_id, type, key) (D10).
func ResolveAsset(ctx context.Context, st Store, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error) {
	if tenantID == domain.NilID {
		return nil, domain.ErrInvalidTenantID
	}
	if key == "" {
		key = "unnamed-asset"
	}

	asset, err := st.LookupAsset(ctx, tenantID, assetType, key)
	if err == nil && asset != nil {
		return asset, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// Create missing asset
	now := time.Now().UTC()
	newAsset := &domain.Asset{
		ID:          domain.NewID(),
		TenantID:    tenantID,
		Type:        assetType,
		Key:         key,
		DisplayName: key,
		Active:      true,
		FirstSeen:   now,
		LastSeen:    now,
	}

	if err := st.CreateAsset(ctx, newAsset); err != nil {
		// Retry lookup in case of race
		if existing, retryErr := st.LookupAsset(ctx, tenantID, assetType, key); retryErr == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}

	return newAsset, nil
}

// ResolveApplication resolves the target application for an asset per D10 priority:
// 1. Asset's existing application_id
// 2. Declared application slug (created if missing)
// 3. Tenant's built-in "unassigned" application (D10 line 154)
func ResolveApplication(ctx context.Context, st Store, tenantID uuid.UUID, asset *domain.Asset, declaredSlug string) (uuid.UUID, error) {
	if asset != nil && asset.ApplicationID != nil && *asset.ApplicationID != domain.NilID {
		return *asset.ApplicationID, nil
	}

	targetSlug := strings.TrimSpace(declaredSlug)
	if targetSlug == "" {
		targetSlug = "unassigned"
	}
	targetSlug = strings.ToLower(targetSlug)

	app, err := st.LookupApplication(ctx, tenantID, targetSlug)
	if err == nil && app != nil {
		// Update asset binding if unassigned
		if asset != nil && (asset.ApplicationID == nil || *asset.ApplicationID == domain.NilID) {
			asset.ApplicationID = &app.ID
			_ = st.CreateAsset(ctx, asset)
		}
		return app.ID, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return domain.NilID, err
	}

	// Create application
	now := time.Now().UTC()
	name := "Unassigned"
	if targetSlug != "unassigned" {
		name = targetSlug
	}
	newApp := &domain.Application{
		ID:                  domain.NewID(),
		TenantID:            tenantID,
		Slug:                targetSlug,
		Name:                name,
		BusinessCriticality: "medium",
		Lifecycle:           "production",
		Version:             1,
		CreatedAt:           now,
	}

	if err := st.CreateApplication(ctx, newApp); err != nil {
		if existing, retryErr := st.LookupApplication(ctx, tenantID, targetSlug); retryErr == nil && existing != nil {
			return existing.ID, nil
		}
		return domain.NilID, err
	}

	if asset != nil {
		asset.ApplicationID = &newApp.ID
		_ = st.CreateAsset(ctx, asset)
	}

	return newApp.ID, nil
}

// ResolveTrack derives the track name from context per D10 line 135:
// default: context.environment, else context.branch when tracked, else default.
func ResolveTrack(uctx domain.UploadContext) string {
	if env := strings.TrimSpace(uctx.Environment); env != "" {
		return env
	}
	if branch := strings.TrimSpace(uctx.Branch); branch != "" {
		return branch
	}
	return "default"
}

// IsEphemeral determines whether a run's ref is ephemeral (e.g. pull requests, feature branches) per D10 line 137.
// Ephemeral runs produce CI gate results but do not alter the persistent inventory.
func IsEphemeral(branch string, trackedRefs []string) bool {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return false
	}

	// Pull request patterns are always ephemeral
	lower := strings.ToLower(branch)
	if strings.HasPrefix(lower, "refs/pull/") ||
		strings.HasPrefix(lower, "pull/") ||
		strings.HasPrefix(lower, "pr/") ||
		strings.HasPrefix(lower, "merge-requests/") {
		return true
	}

	if len(trackedRefs) == 0 {
		trackedRefs = []string{"main", "master", "default", "release/*", "prod", "production"}
	}

	for _, ref := range trackedRefs {
		if ref == branch {
			return false
		}
		if strings.HasSuffix(ref, "/*") {
			prefix := strings.TrimSuffix(ref, "/*")
			if strings.HasPrefix(branch, prefix+"/") {
				return false
			}
		}
	}

	return true
}
