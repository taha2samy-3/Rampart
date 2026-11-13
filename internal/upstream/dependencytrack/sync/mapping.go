package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
	"rampart/internal/domain"
	dtclient "rampart/internal/upstream/dependencytrack/client"
)

// MappingRuleConfig defines CEL rules for project mapping.
type CELRule struct {
	When        string
	Application string
	program     cel.Program
}

// MappingConfig configures the 7-step mapping engine (docs/10 §3).
type MappingConfig struct {
	UseProjectProperties bool
	TagPrefix            string // default "rampart-app:"
	MatchExistingAssets  bool
	ParentAsApplication  bool
	CELRules             []CELRule
	DefaultApplication   string
}

// AssetFinder allows looking up existing assets by key or dtrack project uuid (Rules 3 & 4).
type AssetFinder interface {
	FindAssetByDTrackUUID(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.Asset, error)
	FindAssetByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Asset, error)
}

// ApplicationResolver resolves application slugs or names to IDs.
type ApplicationResolver interface {
	GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error)
}

// MappingResult describes the outcome of applying the mapping rules to a project.
type MappingResult struct {
	ApplicationID   *uuid.UUID
	ApplicationSlug string
	MatchedRule     string
	UnmappedReason  string
}

// MappingEngine applies the 7 identity mapping rules in strict order (docs/10 §3).
type MappingEngine struct {
	cfg    MappingConfig
	assets AssetFinder
	apps   ApplicationResolver
	celEnv *cel.Env
}

// NewMappingEngine creates an initialized MappingEngine.
func NewMappingEngine(cfg MappingConfig, assets AssetFinder, apps ApplicationResolver) (*MappingEngine, error) {
	if cfg.TagPrefix == "" {
		cfg.TagPrefix = "rampart-app:"
	}

	env, err := cel.NewEnv(
		cel.Variable("project", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing CEL environment for project mapping: %w", err)
	}

	for i, r := range cfg.CELRules {
		if r.When != "" {
			ast, issues := env.Compile(r.When)
			if issues != nil && issues.Err() != nil {
				return nil, fmt.Errorf("compiling CEL rule %q: %w", r.When, issues.Err())
			}
			prg, err := env.Program(ast)
			if err != nil {
				return nil, fmt.Errorf("creating CEL program for %q: %w", r.When, err)
			}
			cfg.CELRules[i].program = prg
		}
	}

	return &MappingEngine{
		cfg:    cfg,
		assets: assets,
		apps:   apps,
		celEnv: env,
	}, nil
}

// Resolve maps a Dependency-Track project to a Rampart application.
func (e *MappingEngine) Resolve(ctx context.Context, tenantID uuid.UUID, proj dtclient.Project, props []dtclient.Property) MappingResult {
	// Rule 1: Project property group=integrations, name=rampart.application
	if e.cfg.UseProjectProperties {
		for _, p := range props {
			if strings.EqualFold(p.Group, "integrations") && strings.EqualFold(p.Name, "rampart.application") {
				slug := strings.TrimSpace(p.Value)
				if slug != "" {
					appID := e.resolveAppID(ctx, tenantID, slug)
					return MappingResult{
						ApplicationID:   appID,
						ApplicationSlug: slug,
						MatchedRule:     "property:rampart.application",
					}
				}
			}
		}
	}

	// Rule 2: Project tag rampart-app:<slug>
	for _, t := range proj.Tags {
		name := strings.TrimSpace(t.Name)
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(e.cfg.TagPrefix)) {
			slug := strings.TrimSpace(name[len(e.cfg.TagPrefix):])
			if slug != "" {
				appID := e.resolveAppID(ctx, tenantID, slug)
				return MappingResult{
					ApplicationID:   appID,
					ApplicationSlug: slug,
					MatchedRule:     "tag:" + e.cfg.TagPrefix,
				}
			}
		}
	}

	// Rule 3: Existing asset link with dtrack_project_uuid
	if e.cfg.MatchExistingAssets && e.assets != nil {
		if asset, err := e.assets.FindAssetByDTrackUUID(ctx, tenantID, proj.UUID); err == nil && asset != nil && asset.ApplicationID != nil {
			return MappingResult{
				ApplicationID: asset.ApplicationID,
				MatchedRule:   "existing_asset:dtrack_project_uuid",
			}
		}
	}

	// Rule 4: purl or repository match
	if e.cfg.MatchExistingAssets && e.assets != nil {
		keysToTest := []string{}
		if proj.Purl != "" {
			keysToTest = append(keysToTest, proj.Purl)
		}
		for _, key := range keysToTest {
			if asset, err := e.assets.FindAssetByKey(ctx, tenantID, key); err == nil && asset != nil && asset.ApplicationID != nil {
				return MappingResult{
					ApplicationID: asset.ApplicationID,
					MatchedRule:   "asset_key_match:" + key,
				}
			}
		}
	}

	// Rule 5: Parent rule: parent project name is application
	if e.cfg.ParentAsApplication && proj.Parent != nil && proj.Parent.Name != "" {
		slug := strings.TrimSpace(proj.Parent.Name)
		appID := e.resolveAppID(ctx, tenantID, slug)
		return MappingResult{
			ApplicationID:   appID,
			ApplicationSlug: slug,
			MatchedRule:     "parent_project:" + slug,
		}
	}

	// Rule 6: CEL rule over project (name, tags, classifier)
	if len(e.cfg.CELRules) > 0 {
		tagNames := make([]any, len(proj.Tags))
		for i, t := range proj.Tags {
			tagNames[i] = t.Name
		}
		projMap := map[string]any{
			"name":       proj.Name,
			"version":    proj.Version,
			"classifier": proj.Classifier,
			"tags":       tagNames,
			"active":     proj.Active,
			"purl":       proj.Purl,
		}
		for _, r := range e.cfg.CELRules {
			if r.program != nil {
				val, _, err := r.program.Eval(map[string]any{"project": projMap})
				if err == nil && val.Value() == true {
					slug := strings.TrimSpace(r.Application)
					appID := e.resolveAppID(ctx, tenantID, slug)
					return MappingResult{
						ApplicationID:   appID,
						ApplicationSlug: slug,
						MatchedRule:     "cel:" + r.When,
					}
				}
			}
		}
	}

	// Rule 7: Fallback to default application or unmapped
	if e.cfg.DefaultApplication != "" {
		slug := strings.TrimSpace(e.cfg.DefaultApplication)
		appID := e.resolveAppID(ctx, tenantID, slug)
		return MappingResult{
			ApplicationID:   appID,
			ApplicationSlug: slug,
			MatchedRule:     "defaultApplication",
		}
	}

	return MappingResult{
		ApplicationID:  nil,
		UnmappedReason: "no matching rule found for project " + proj.Name,
	}
}

func (e *MappingEngine) resolveAppID(ctx context.Context, tenantID uuid.UUID, slug string) *uuid.UUID {
	if e.apps == nil || slug == "" {
		return nil
	}
	app, err := e.apps.GetApplicationBySlug(ctx, tenantID, slug)
	if err == nil && app != nil {
		return &app.ID
	}
	return nil
}
