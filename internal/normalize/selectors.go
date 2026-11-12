package normalize

import (
	"strings"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// AppSelectors is one application's selectors, as the matcher needs them.
type AppSelectors struct {
	ID        uuid.UUID
	Slug      string
	Selectors domain.Selectors
}

// MatchApplication finds the application whose selectors match an asset (D10 step (b), D56). Patterns are
// normalized exactly as asset keys are, so "git@github.com:Acme/Shop.git" matches the key
// "https://github.com/acme/shop". The most specific pattern wins: an exact key over any prefix, a longer prefix
// over a shorter one; between equally specific patterns of two applications the smaller slug wins, so the answer
// never depends on the order rows come back in.
func MatchApplication(apps []AppSelectors, assetType domain.AssetType, key string) (uuid.UUID, bool) {
	var best uuid.UUID
	bestScore, bestSlug := 0, ""
	for _, a := range apps {
		var patterns []string
		switch assetType {
		case domain.AssetRepository:
			for _, r := range a.Selectors.Repositories {
				patterns = append(patterns, r.URL)
			}
		case domain.AssetImage:
			for _, i := range a.Selectors.Images {
				patterns = append(patterns, i.Repository)
			}
		}
		for _, p := range patterns {
			score := selectorScore(assetType, p, key)
			if score == 0 {
				continue
			}
			if score > bestScore || (score == bestScore && a.Slug < bestSlug) {
				best, bestScore, bestSlug = a.ID, score, a.Slug
			}
		}
	}
	return best, bestScore > 0
}

// exactBonus puts any exact match above any prefix match.
const exactBonus = 1 << 20

// selectorScore is 0 when the pattern does not match, the length of the prefix for a prefix pattern, and more
// than any prefix for an exact one.
func selectorScore(assetType domain.AssetType, pattern, key string) int {
	pattern = strings.TrimSpace(pattern)
	norm := func(v string) string {
		if assetType == domain.AssetImage {
			return ImageRef(v)
		}
		return RepositoryURL(v)
	}
	if !strings.HasSuffix(pattern, "*") {
		if norm(pattern) == key {
			return exactBonus + len(key)
		}
		return 0
	}
	raw := strings.TrimSuffix(pattern, "*")
	prefix := norm(raw)
	// "github.com/acme/*" means the repositories under acme/, not also "acme-tools": keep the slash that the
	// normalizer trims.
	if strings.HasSuffix(raw, "/") && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if prefix != "" && strings.HasPrefix(key, prefix) {
		return len(prefix)
	}
	return 0
}
