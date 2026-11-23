package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
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
	// ComplianceScope names the compliance scopes the application is in (for example pci, sox): a framework with
	// appliesTo.complianceScope reads only the applications that list it (docs/16 D102).
	ComplianceScope []string  `json:"complianceScope,omitempty"`
	Lifecycle       string    `json:"lifecycle,omitempty"`
	Hierarchy       []string  `json:"hierarchy,omitempty"`
	Selectors       Selectors `json:"selectors,omitempty"`
	// Type is what kind of thing the application is (D140). "repo" is built: it names one branch of one repository, with
	// Repository and Branch. "machine" is designed and refused until a host source exists. Empty is a repository-wide
	// application, as before, and takes neither Repository nor Branch.
	Type        string         `json:"type,omitempty"`
	Repository  string         `json:"repository,omitempty"`
	Branch      string         `json:"branch,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

// ApplicationTypes are the types an Application resource may name today.
var ApplicationTypes = []string{"repo"}

// Environments are the values of an application's environment (D140). It has no default: an application that does not
// say is not described, and the score gives it no environment points.
var Environments = []string{"production", "staging", "test", "development"}

// validateIdentity checks type, repository, branch and environment together, and returns them normalised.
func (s ApplicationSpec) validateIdentity() (typ, repository, branch, environment string, err error) {
	typ = strings.ToLower(strings.TrimSpace(s.Type))
	repository, branch = strings.TrimSpace(s.Repository), strings.TrimSpace(s.Branch)
	switch typ {
	case "", "repo":
	case "machine":
		return "", "", "", "", fmt.Errorf("type machine is designed but not built: no host source exists yet, so only type repo is accepted")
	default:
		return "", "", "", "", fmt.Errorf("type %q is not one of %s", s.Type, strings.Join(ApplicationTypes, ", "))
	}
	if typ == "repo" {
		if repository == "" || branch == "" {
			return "", "", "", "", fmt.Errorf("type repo needs repository and branch: an application is one branch of one repository")
		}
		if strings.ContainsAny(repository, "* \t") {
			return "", "", "", "", fmt.Errorf("repository %q must be one repository address, with no * and no spaces", s.Repository)
		}
		if strings.ContainsAny(branch, "* \t") {
			return "", "", "", "", fmt.Errorf("branch %q must be one branch name, with no * and no spaces (an application is one branch)", s.Branch)
		}
	} else if repository != "" || branch != "" {
		return "", "", "", "", fmt.Errorf("repository and branch need type repo")
	}
	environment = strings.ToLower(strings.TrimSpace(s.Environment))
	if environment != "" && !slices.Contains(Environments, environment) {
		return "", "", "", "", fmt.Errorf("environment %q is not one of %s", s.Environment, strings.Join(Environments, ", "))
	}
	return typ, repository, branch, environment, nil
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

// complianceScopeRe is the shape of a compliance scope, the same as a framework's appliesTo.complianceScope (D102).
var complianceScopeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,63}$`)

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
	var scopes []string
	seenScope := map[string]bool{}
	for _, c := range s.ComplianceScope {
		if !complianceScopeRe.MatchString(c) {
			return Application{}, fmt.Errorf("complianceScope %q: lower-case letters, digits and - . _ :, starting with a letter or digit", c)
		}
		if !seenScope[c] {
			seenScope[c] = true
			scopes = append(scopes, c)
		}
	}
	if err := s.Selectors.validate(); err != nil {
		return Application{}, err
	}
	typ, repository, branch, environment, err := s.validateIdentity()
	if err != nil {
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
	var hierarchyPath string
	if len(s.Hierarchy) > 0 {
		var parts []string
		for _, h := range s.Hierarchy {
			sh := slugifySpec(h)
			if sh != "" {
				parts = append(parts, sh)
			}
		}
		hierarchyPath = strings.Join(parts, ".")
	}
	return Application{
		ID: id, TenantID: tenantID, Slug: slug, Name: name, BusinessCriticality: crit, InternetFacing: s.InternetFacing,
		Owners: s.Owners, DataClassification: classes, CompensatingControls: controls, Lifecycle: lifecycle,
		ComplianceScope: scopes, HierarchyPath: hierarchyPath, Type: typ, Repository: repository, Branch: branch, Environment: environment,
		Attributes: s.Attributes,
		Selectors:  Selectors{Repositories: s.Selectors.Repositories, Images: s.Selectors.Images},
	}, nil
}

func slugifySpec(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			out = append(out, r)
		} else if r == '-' || r == ' ' || r == '.' {
			out = append(out, '_')
		}
	}
	return strings.Trim(string(out), "_")
}
