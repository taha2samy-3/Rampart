package ingest

import (
	"context"
	"errors"
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

// NormalizeRepositoryURL and NormalizeImageRef live in internal/normalize so the store can match application
// selectors with the same rules (D56).
func NormalizeRepositoryURL(raw string) string { return normalize.RepositoryURL(raw) }

// NormalizeImageRef strips tags and digests from an image reference (D10).
func NormalizeImageRef(ref string) string { return normalize.ImageRef(ref) }

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

// selectorStore is what selector resolution needs from the store (PostgreSQL; the in-memory store has no
// selectors and keeps the old order).
type selectorStore interface {
	ListApplicationSelectors(ctx context.Context, tenantID uuid.UUID) ([]normalize.AppSelectors, error)
	MoveAssetToApplication(ctx context.Context, tenantID, assetID, appID uuid.UUID) (bool, error)
}

// ResolveApplication resolves the application of an asset in the order of D10, and records it on the asset:
//  1. the application the asset already belongs to, unless that is the tenant's Unassigned application;
//  2. the application whose selectors match the asset key (D56);
//  3. the application the upload names (created if missing);
//  4. the tenant's built-in Unassigned application.
//
// An asset in Unassigned is resolved again on every run, so a selector declared after the first scan still
// claims it. Moving an asset moves its findings in the same transaction.
func ResolveApplication(ctx context.Context, st Store, tenantID uuid.UUID, asset *domain.Asset, declaredSlug string) (uuid.UUID, error) {
	sel, hasSelectors := st.(selectorStore)
	if asset != nil && asset.ApplicationID != nil && *asset.ApplicationID != domain.NilID {
		if !hasSelectors {
			return *asset.ApplicationID, nil
		}
		if cur, err := st.GetApplication(ctx, tenantID, *asset.ApplicationID); err != nil || cur == nil || cur.Slug != "unassigned" {
			return *asset.ApplicationID, nil
		}
	}

	bind := func(appID uuid.UUID) (uuid.UUID, error) {
		if asset == nil {
			return appID, nil
		}
		if hasSelectors {
			if _, err := sel.MoveAssetToApplication(ctx, tenantID, asset.ID, appID); err != nil {
				return domain.NilID, err
			}
		} else if asset.ApplicationID == nil || *asset.ApplicationID == domain.NilID {
			_ = st.CreateAsset(ctx, asset)
		}
		asset.ApplicationID = &appID
		return appID, nil
	}

	if hasSelectors && asset != nil {
		apps, err := sel.ListApplicationSelectors(ctx, tenantID)
		if err != nil {
			return domain.NilID, err
		}
		if appID, ok := normalize.MatchApplication(apps, asset.Type, asset.Key); ok {
			return bind(appID)
		}
	}

	targetSlug := strings.ToLower(strings.TrimSpace(declaredSlug))
	if targetSlug == "" {
		targetSlug = "unassigned"
	}
	if asset != nil && asset.ApplicationID != nil && *asset.ApplicationID != domain.NilID && targetSlug == "unassigned" {
		return *asset.ApplicationID, nil // already in Unassigned, and nothing claims it
	}

	app, err := st.LookupApplication(ctx, tenantID, targetSlug)
	if err == nil && app != nil {
		return bind(app.ID)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return domain.NilID, err
	}

	name := "Unassigned"
	if targetSlug != "unassigned" {
		name = targetSlug
	}
	newApp := &domain.Application{
		ID: domain.NewID(), TenantID: tenantID, Slug: targetSlug, Name: name,
		BusinessCriticality: "medium", Lifecycle: "production", Version: 1, CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateApplication(ctx, newApp); err != nil {
		existing, retryErr := st.LookupApplication(ctx, tenantID, targetSlug)
		if retryErr != nil || existing == nil {
			return domain.NilID, err
		}
		return bind(existing.ID)
	}
	return bind(newApp.ID)
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
