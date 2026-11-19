package query

import (
	"encoding/json"
	"net/http"
	"rampart/internal/wasmstore"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/integrations/mapping"
)

// handleListParsers returns the parsers installed for the cluster and the parser packages this tenant installed (docs/19 §2, §4,
// docs/13 §9, D98). A package that does not validate is left out here; the Integrations page shows it with its error.
func (a *API) handleListParsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	// The parsers installed for the whole cluster (ClusterParser, ClusterSBOMParser) come from the control plane; none is
	// compiled into the server. One that does not validate is left out here, and the resource's status says why.
	parsers := []integrations.Descriptor{}
	if ps, ok := a.store.(domain.ParserStore); ok {
		if list, err := ps.ListParsers(r.Context(), tenantID); err == nil {
			for _, p := range list {
				if p.Origin != "cluster" || p.Error != "" {
					continue
				}
				if d, err := integrations.InstalledDescriptor(p.Name, p.Spec); err == nil {
					// Listed means it can run: a parser whose module is not on this server says so, rather than failing at the first upload.
					if names := integrations.InstalledModuleNames(p.Name, p.Spec); len(names) > 0 && !wasmstore.Default().Has(names...) {
						d.Unavailable = "its WASM module is not installed on this server (parsers.delivery in the chart)"
					}
					parsers = append(parsers, d)
				}
			}
		}
	}
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
