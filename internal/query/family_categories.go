package query

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// familyCategories is what the tenant itself says a scanner family evidences, for the families Rampart's own map
// does not know (D102): a parser package declares its category, and is recorded under "mapping:<name>" for a run
// that found nothing and under its family for the findings; any other family counts for the categories of the
// findings it produced. fromFindings is family -> categories from the findings.
func (a *API) familyCategories(ctx context.Context, tenantID uuid.UUID, fromFindings map[string][]string) map[string][]string {
	out := map[string][]string{}
	for fam, cats := range fromFindings {
		out[fam] = cats
	}
	pkgs, ok := a.store.(domain.IntegrationPackages)
	if !ok {
		return out
	}
	list, err := pkgs.ListIntegrationPackages(ctx, tenantID)
	if err != nil {
		return out
	}
	for _, p := range list {
		if p.Kind != "parser" || p.Error != "" {
			continue
		}
		var spec struct {
			Family   string `json:"family"`
			Category string `json:"category"`
		}
		if json.Unmarshal(p.Spec, &spec) != nil || spec.Category == "" {
			continue
		}
		out["mapping:"+p.Name] = []string{spec.Category}
		if spec.Family != "" {
			out[spec.Family] = appendNew(out[spec.Family], spec.Category)
		}
	}
	return out
}

func appendNew(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}
