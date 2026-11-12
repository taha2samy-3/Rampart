package domain

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// ApplicationSpec is the spec of an Application resource (docs/04), shared by the operator and `rampart apply`
// so both turn the same YAML into the same row (D3, D55).
type ApplicationSpec struct {
	DisplayName          string   `json:"displayName"`
	BusinessCriticality  string   `json:"businessCriticality,omitempty"`
	InternetFacing       bool     `json:"internetFacing,omitempty"`
	Owners               []string `json:"owners,omitempty"`
	DataClassification   []string `json:"dataClassification,omitempty"`
	CompensatingControls []string `json:"compensatingControls,omitempty"`
	Lifecycle            string   `json:"lifecycle,omitempty"`
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
	}, nil
}

// ControlCovers says whether one of an application's compensating controls reduces the risk of a finding of
// this category (docs/06 section 2: "compensating control relevant to category"). A web application firewall
// or an API gateway inspects HTTP requests, so it counts against what a dynamic scan found through HTTP (PCI DSS
// 4.0.1 requirement 6.4.2 describes a WAF as detecting and preventing web-based attacks); docs/04 gives the same
// rule as its example. mTLS and a private network change who can reach the application at all, which the
// internet-exposure factor already carries, so they are recorded and not counted twice.
func ControlCovers(controls []string, category FindingCategory) bool {
	if category != CategoryDAST {
		return false
	}
	for _, c := range controls {
		if c == "waf" || c == "api_gateway" {
			return true
		}
	}
	return false
}
