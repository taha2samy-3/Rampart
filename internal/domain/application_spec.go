package domain

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// ApplicationSpec is the spec of an Application resource (docs/04), shared by the operator and `rampart apply`
// so both turn the same YAML into the same row (D3, D55).
type ApplicationSpec struct {
	DisplayName          string    `json:"displayName"`
	BusinessCriticality  string    `json:"businessCriticality,omitempty"`
	InternetFacing       bool      `json:"internetFacing,omitempty"`
	Owners               []string  `json:"owners,omitempty"`
	DataClassification   []string  `json:"dataClassification,omitempty"`
	CompensatingControls []string  `json:"compensatingControls,omitempty"`
	Lifecycle            string    `json:"lifecycle,omitempty"`
	Selectors            Selectors `json:"selectors,omitempty"`
}

// Selectors attach assets to an application automatically (docs/04, D10 resolution step (b), D56). A pattern is
// an exact key or a prefix ending in "*". Workloads need a connected cluster (the collector, after v1.0, D21).
type Selectors struct {
	Repositories []RepositorySelector `json:"repositories,omitempty"`
	Images       []ImageSelector      `json:"images,omitempty"`
	Workloads    []json.RawMessage    `json:"workloads,omitempty"`
}

// RepositorySelector matches repository assets by clone URL.
type RepositorySelector struct {
	URL string `json:"url"`
}

// ImageSelector matches image assets by registry/repository (no tag, no digest).
type ImageSelector struct {
	Repository string `json:"repository"`
}

// Empty says the application declares no selector.
func (s Selectors) Empty() bool { return len(s.Repositories) == 0 && len(s.Images) == 0 }

func (s Selectors) validate() error {
	if len(s.Workloads) > 0 {
		return fmt.Errorf("selectors.workloads is not built: it needs a connected cluster (the collector, after v1.0)")
	}
	check := func(field, v string) error {
		v = strings.TrimSpace(v)
		if v == "" || v == "*" {
			return fmt.Errorf("%s must name a key or a prefix ending in *", field)
		}
		if strings.Contains(strings.TrimSuffix(v, "*"), "*") {
			return fmt.Errorf("%s %q: * is allowed only at the end", field, v)
		}
		return nil
	}
	for _, r := range s.Repositories {
		if err := check("selectors.repositories[].url", r.URL); err != nil {
			return err
		}
	}
	for _, i := range s.Images {
		if err := check("selectors.images[].repository", i.Repository); err != nil {
			return err
		}
	}
	return nil
}

// Data classifications (docs/03). pii, pci and phi add the sensitive-data factor of the score (docs/06).
var dataClassifications = map[string]bool{"pii": true, "pci": true, "phi": true, "secret": true, "public": true}

// Compensating controls (docs/03). The resource spells them in camelCase, the database in snake_case (D17).
var compensatingControls = map[string]string{
	"waf": "waf", "apiGateway": "api_gateway", "mtls": "mtls", "privateNetwork": "private_network",
}

// ToApplication validates the spec and builds the application it describes. Unknown values are refused, not
// dropped, so a typo in a resource shows as Ready=False instead of a silently lower score.
func (s ApplicationSpec) ToApplication(id, tenantID uuid.UUID, slug string) (Application, error) {
	crit := strings.ToLower(s.BusinessCriticality)
	switch crit {
	case "":
		crit = "medium"
	case "critical", "high", "medium", "low":
	default:
		return Application{}, fmt.Errorf("businessCriticality %q is not one of critical, high, medium, low", s.BusinessCriticality)
	}
	var classes []string
	for _, c := range s.DataClassification {
		c = strings.ToLower(strings.TrimSpace(c))
		if !dataClassifications[c] {
			return Application{}, fmt.Errorf("dataClassification %q is not one of pii, pci, phi, secret, public", c)
		}
		classes = append(classes, c)
	}
	var controls []string
	for _, c := range s.CompensatingControls {
		v, ok := compensatingControls[strings.TrimSpace(c)]
		if !ok {
			return Application{}, fmt.Errorf("compensatingControls %q is not one of waf, apiGateway, mtls, privateNetwork", c)
		}
		controls = append(controls, v)
	}
	if err := s.Selectors.validate(); err != nil {
		return Application{}, err
	}
	lifecycle := s.Lifecycle
	if lifecycle == "" {
		lifecycle = "production"
	}
	name := s.DisplayName
	if name == "" {
		name = slug
	}
	return Application{
		ID: id, TenantID: tenantID, Slug: slug, Name: name, BusinessCriticality: crit, InternetFacing: s.InternetFacing,
		Owners: s.Owners, DataClassification: classes, CompensatingControls: controls, Lifecycle: lifecycle,
		Selectors: Selectors{Repositories: s.Selectors.Repositories, Images: s.Selectors.Images},
	}, nil
}
