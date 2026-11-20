package query

import (
	"encoding/json"
	"net/http"
	"rampart/internal/wasmstore"
	"strings"
	"time"

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

	// The parsers installed for the whole cluster (ClusterParser, ClusterSBOMParser) come from the control plane; none is compiled into the
	// server. A resource that was refused is listed too, with its reason, so the page can say whether each parser is installed correctly.
	parsers := []parserItem{}
	if ps, ok := a.store.(domain.ParserStore); ok {
		if list, err := ps.ListParsers(r.Context(), tenantID); err == nil {
			for _, p := range list {
				if p.Origin != "cluster" {
					continue
				}
				parsers = append(parsers, clusterParserItem(p))
			}
		}
	}
	if pkgs, ok := a.store.(domain.IntegrationPackages); ok {
		if list, err := pkgs.ListIntegrationPackages(r.Context(), tenantID); err == nil {
			for _, p := range list {
				if p.Kind != "parser" {
					continue
				}
				if p.Error != "" {
					parsers = append(parsers, parserItem{Descriptor: integrations.Descriptor{ID: "mapping:" + p.Name, Name: p.Name, Kind: integrations.KindParser, SupportLevel: integrations.SupportCommunity},
						Family: "report", Runtime: "mapping", Origin: "tenant", Status: "refused", Error: p.Error,
						ResourceKind: "Parser", ResourceName: p.Name})
					continue
				}
				if mp, err := mapping.NewParserFromSpec(p.Name, p.Spec); err == nil {
					d := mp.Descriptor()
					d.SupportLevel = integrations.SupportCommunity // installed by the tenant, not shipped
					parsers = append(parsers, parserItem{Descriptor: d, Family: "report", Runtime: "mapping", Origin: "tenant", Status: "ready",
						ResourceKind: "Parser", ResourceName: p.Name})
				}
			}
		}
	}

	if rs, ok := a.store.(domain.ParserRunStore); ok {
		if last, err := rs.LastRunByParser(r.Context(), tenantID); err == nil {
			for i := range parsers {
				id := parsers[i].ID
				clean := strings.TrimPrefix(strings.TrimPrefix(id, "cluster:"), "builtin:")
				lr, found := last[id]
				if !found {
					lr, found = last["cluster:"+clean]
				}
				if !found {
					lr, found = last["builtin:"+clean]
				}
				if !found {
					lr, found = last[clean]
				}
				if found {
					parsers[i].LastRun = &parserRun{ID: lr.RunID.String(), Status: string(lr.Status), Error: lr.Error, At: lr.At}
					parsers[i].LastSuccess = lr.LastSuccess
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

// parserItem is one installed parser as the Parsers page shows it: what it is (report parser or SBOM reader, and the runtime it runs on), where
// it came from, and whether it is installed correctly: ready, its module missing, or its resource refused with the reason.
type parserItem struct {
	integrations.Descriptor
	Family       string `json:"family"`                  // report | sbom
	Runtime      string `json:"runtime,omitempty"`       // wasm | lua | mapping
	Origin       string `json:"origin"`                  // cluster | tenant
	Module       string `json:"module,omitempty"`        // the WASM module it needs, by name
	Status       string `json:"status"`                  // ready | module_missing | refused
	Error        string `json:"error,omitempty"`         // why the resource was refused
	ResourceKind string `json:"resource_kind,omitempty"` // ClusterParser | ClusterSBOMParser | Parser
	ResourceName string `json:"resource_name,omitempty"` // e.g. bandit, cyclonedx, acme-audit
	// LastRun is the last run that used this parser (absent if none has) and LastSuccess the last time one completed.
	LastRun     *parserRun `json:"last_run,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
}

type parserRun struct {
	ID     string    `json:"id"`
	Status string    `json:"status"`
	Error  string    `json:"error,omitempty"`
	At     time.Time `json:"at"`
}

func clusterParserItem(p domain.StoredParserObject) parserItem {
	family, runtime, ok := integrations.InstalledInfo(p.Spec)
	if !ok {
		family = "report"
		if strings.HasPrefix(p.Name, domain.SBOMParserNamePrefix) {
			family = "sbom"
		}
	}
	resourceKind := "ClusterParser"
	resourceName := p.Name
	if family == "sbom" {
		resourceKind = "ClusterSBOMParser"
		resourceName = strings.TrimPrefix(p.Name, domain.SBOMParserNamePrefix)
	}
	id := "cluster:" + p.Name
	if family == "sbom" {
		id = "cluster:sbom-" + resourceName
	}
	if p.Error != "" || !ok {
		why := p.Error
		if why == "" {
			why = "the resource could not be read"
		}
		return parserItem{
			Descriptor:   integrations.Descriptor{ID: id, Name: p.Name, Kind: integrations.KindParser, SupportLevel: integrations.SupportCluster},
			Family:       family,
			Runtime:      runtime,
			Origin:       "cluster",
			Status:       "refused",
			Error:        why,
			ResourceKind: resourceKind,
			ResourceName: resourceName,
		}
	}
	d, err := integrations.InstalledDescriptor(p.Name, p.Spec)
	if err != nil {
		return parserItem{
			Descriptor:   integrations.Descriptor{ID: id, Name: p.Name, Kind: integrations.KindParser, SupportLevel: integrations.SupportCluster},
			Family:       family,
			Runtime:      runtime,
			Origin:       "cluster",
			Status:       "refused",
			Error:        err.Error(),
			ResourceKind: resourceKind,
			ResourceName: resourceName,
		}
	}
	it := parserItem{
		Descriptor:   d,
		Family:       family,
		Runtime:      runtime,
		Origin:       "cluster",
		Status:       "ready",
		ResourceKind: resourceKind,
		ResourceName: resourceName,
	}
	// Listed as ready only when it can run: a parser whose module is not on this server says so, rather than failing at the first upload.
	if names := integrations.InstalledModuleNames(p.Name, p.Spec); len(names) > 0 {
		it.Module = names[0]
		if !wasmstore.Default().Has(names...) {
			it.Status = "module_missing"
			it.Unavailable = "its WASM module is not installed on this server (parsers.delivery in the chart)"
		}
	}
	return it
}
