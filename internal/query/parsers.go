package query

import (
	"encoding/json"
	"net/http"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/integrations/mapping"
)

// handleListParsers returns the built-in parsers and the parser packages this tenant installed (docs/19 §2, §4,
// docs/13 §9, D98). A package that does not validate is left out here; the Integrations page shows it with its error.
func (a *API) handleListParsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	parsers := integrations.DefaultRegistry().ListParsers()
	if pkgs, ok := a.store.(domain.IntegrationPackages); ok {
		if list, err := pkgs.ListIntegrationPackages(r.Context(), tenantID); err == nil {
			for _, p := range list {
				if p.Kind != "parser" || p.Error != "" {
					continue
				}
				if mp, err := mapping.NewParserFromSpec(p.Name, p.Spec); err == nil {
					d := mp.Descriptor()
					d.SupportLevel = integrations.SupportCommunity // installed by the tenant, not shipped
					parsers = append(parsers, d)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"parsers": parsers,
		"total":   len(parsers),
	})
}
