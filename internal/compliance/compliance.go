// Package compliance holds the frameworks the Compliance screen shows and the rule for reading a control's
// status (docs/16 D52). The frameworks are data (docs/03: data-driven taxonomies): JSON files embedded in the
// binary, each a list of controls that are matched to findings by weakness (CWE) or by the kind of scan.
package compliance

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.json
var files embed.FS

// Control is one requirement of a framework.
type Control struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	CWEs        []int       `json:"cwes,omitempty"`       // findings with any of these weaknesses count
	Categories  []string    `json:"categories,omitempty"` // findings of these categories count, and these scans evidence it
	Rules       []RuleMatch `json:"rules,omitempty"`      // findings raised by these rules count (D102)
	MinSeverity string      `json:"minSeverity,omitempty"`
	Evidence    []string    `json:"evidence,omitempty"` // the scan categories that must have run; see EvidenceCategories
	Manual      bool        `json:"manual,omitempty"`   // attested by a person, not matched to findings
	Rank        int         `json:"rank,omitempty"`
}

// Framework is a versioned list of controls.
type Framework struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Source     string    `json:"source"`
	LogoURL    string    `json:"-"`    // read by the server only (GET /taxonomies/{id}/logo); never sent to the browser
	Kind       string    `json:"kind"` // cwe: matched by weakness; category: by the kind of scan; custom: a resource (D102)
	Note       string    `json:"note,omitempty"`
	Origin     string    `json:"origin,omitempty"`      // builtin | cluster | tenant
	Scope      string    `json:"scope,omitempty"`       // only applications whose complianceScope lists it
	WindowDays int       `json:"window_days,omitempty"` // how recent a scan must be to count; 0 is the default 30
	Controls   []Control `json:"controls"`
}

// DefaultWindowDays is how recent a scan must be to evidence a control, unless the framework says otherwise.
const DefaultWindowDays = 30

// Window is the framework's evidence window in days.
func (f Framework) Window() int {
	if f.WindowDays > 0 {
		return f.WindowDays
	}
	return DefaultWindowDays
}

var (
	once sync.Once
	all  []Framework
	err  error
)

func load() {
	entries, e := files.ReadDir("data")
	if e != nil {
		err = e
		return
	}
	for _, ent := range entries {
		b, e := files.ReadFile("data/" + ent.Name())
		if e != nil {
			err = e
			return
		}
		var f Framework
		if e := json.Unmarshal(b, &f); e != nil {
			err = fmt.Errorf("compliance: %s: %w", ent.Name(), e)
			return
		}
		if f.Kind == "" {
			f.Kind = "cwe"
		}
		f.Origin = "builtin"
		if e := f.validate(); e != nil {
			err = fmt.Errorf("compliance: %s: %w", ent.Name(), e)
			return
		}
		all = append(all, f)
	}
	// By name, and the newest version of a framework first (OWASP Top 10 2025 before 2021), so the order and the
	// default the UI shows never depend on the order files are read in.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].Version > all[j].Version
	})
}

func (f Framework) validate() error {
	if f.ID == "" || f.Name == "" || len(f.Controls) == 0 {
		return fmt.Errorf("a framework needs an id, a name and controls")
	}
	seen := map[string]bool{}
	for _, c := range f.Controls {
		if c.ID == "" || c.Name == "" || seen[c.ID] {
			return fmt.Errorf("control %q: missing or repeated id or name", c.ID)
		}
		seen[c.ID] = true
		if len(c.CWEs) == 0 && len(c.Categories) == 0 {
			return fmt.Errorf("control %s matches nothing", c.ID)
		}
		for _, cat := range c.Categories {
			if !knownCategory[cat] {
				return fmt.Errorf("control %s: unknown category %q", c.ID, cat)
			}
		}
	}
	return nil
}

var knownCategory = map[string]bool{"sast": true, "sca": true, "secret": true, "iac": true, "container": true, "dast": true, "cspm": true, "compliance": true, "license": true, "supply_chain": true}

// All returns the frameworks, sorted by name.
func All() ([]Framework, error) {
	once.Do(load)
	return all, err
}

// Get returns one framework by id.
func Get(id string) (*Framework, bool) {
	fs, err := All()
	if err != nil {
		return nil, false
	}
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i], true
		}
	}
	return nil, false
}

// FamilyCategories says which kinds of finding a scanner family evidences. A control whose scans never ran is
// "not assessed" rather than "clear": no findings from a scan that did not happen prove nothing. Use CategoriesOf,
// which also reads parser ids and the families a tenant installed (D102).
var FamilyCategories = map[string][]string{
	"semgrep": {"sast", "secret"}, "sarif": {"sast"}, "gitleaks": {"secret"}, "trufflehog": {"secret"},
	"trivy": {"sca", "container", "iac", "secret"}, "grype": {"sca", "container"},
	"zap": {"dast"}, "nuclei": {"dast"}, "checkov": {"iac"}, "kics": {"iac"}, "prowler": {"cspm"},
	"bandit": {"sast"}, "dependency-check": {"sca"}, "snyk": {"sca", "sast", "container"}, "kube-bench": {"compliance", "cspm"},
	"gitlab-sast": {"sast"}, "gitlab-secret-detection": {"secret"}, "gitlab-dependency-scanning": {"sca"},
	"gitlab-container-scanning": {"sca", "container"}, "gitlab-dast": {"dast"},
	// SARIF tools the normaliser names (normalize.CanonicalScannerFamily).
	"codeql": {"sast"}, "osv-scanner": {"sca"}, "hadolint": {"iac"}, "scorecard": {"supply_chain"},
	// SBOM readers: an SBOM is a component inventory, evidence for dependency checks.
	"cyclonedx": {"sca"}, "spdx": {"sca"},
}

// parserFamily is the family a parser id stands for. A run that found nothing is recorded under its parser's id
// ("builtin:semgrep"), not the tool's name: without this, a clean scan would never count as evidence.
var parserFamily = map[string]string{"dependencycheck": "dependency-check", "kubebench": "kube-bench"}

// CategoriesOf returns what a scanner family evidences: the built-in map, then the parser id it may be written as,
// then extra (what the tenant knows: a parser package's declared category, or what the family produced). A family
// nothing knows evidences nothing.
func CategoriesOf(family string, extra map[string][]string) []string {
	f := strings.ToLower(family)
	if c, ok := FamilyCategories[f]; ok {
		return c
	}
	if rest, ok := strings.CutPrefix(f, "builtin:"); ok {
		if alias, ok := parserFamily[rest]; ok {
			rest = alias
		}
		if c, ok := FamilyCategories[rest]; ok {
			return c
		}
	}
	return extra[family]
}

// Status is a control's reading.
type Status string

const (
	StatusOpen        Status = "open"         // findings that bear on it are open and at least one is past its deadline: out of compliance
	StatusAtRisk      Status = "at_risk"      // findings that bear on it are open, none is past its deadline yet: fix them before the first falls due
	StatusClear       Status = "clear"        // assessed, and none are open
	StatusNotAssessed Status = "not_assessed" // no scan that could evidence it ran lately
)

// codeScans are what can find a weakness in the application's own code. A dependency or image scan finds CWEs too,
// but in other people's code: it does not assess an injection control for this application (D102).
var codeScans = []string{"sast", "dast"}

// EvidenceCategories are the kinds of scan that must have run for the control to be read: what it says, else the
// categories it matches, else (matched by CWE only) a code scan. A control matched only by rules is evidenced by
// its rules' scanners, which Assessed checks by family.
func (c Control) EvidenceCategories() []string {
	switch {
	case len(c.Evidence) > 0:
		return c.Evidence
	case len(c.Categories) > 0:
		return c.Categories
	case len(c.CWEs) > 0:
		return codeScans
	}
	return nil
}

// Assessed says whether the control has evidence: a scan of a kind it needs ran in the window, or one of the
// scanners its rules name ran. scanned is by category, families by scanner family.
func (c Control) Assessed(scanned, families map[string]bool) bool {
	for _, cat := range c.EvidenceCategories() {
		if scanned[cat] {
			return true
		}
	}
	for _, r := range c.Rules {
		if families[r.ScannerFamily] {
			return true
		}
	}
	return false
}

// Query is the findings filter that lists what bears on a control, in the grammar of docs/11, and whether it lists
// all of it. The grammar has no "or" across fields, so a control matched by CWE and by category (or rule) gets the
// filter of its CWEs, and exact is false: the screen then says the link shows part of the count, rather than
// letting the two numbers differ without a word (D102).
func (c Control) Query() (q string, exact bool) {
	var parts []string
	kinds := 0
	for _, has := range []bool{len(c.CWEs) > 0, len(c.Categories) > 0, len(c.Rules) > 0} {
		if has {
			kinds++
		}
	}
	exact = kinds == 1 && c.MinSeverity == ""
	switch {
	case len(c.CWEs) > 0:
		cw := make([]string, len(c.CWEs))
		for i, n := range c.CWEs {
			cw[i] = fmt.Sprint(n)
		}
		parts = append(parts, "cwe:"+strings.Join(cw, ","))
	case len(c.Categories) > 0:
		parts = append(parts, "category:"+strings.Join(c.Categories, ","))
	case len(c.Rules) > 0:
		fams, rules := []string{}, []string{}
		for _, r := range c.Rules {
			if strings.HasSuffix(r.RuleID, "*") {
				exact = false
				continue
			}
			if !contains(fams, r.ScannerFamily) {
				fams = append(fams, r.ScannerFamily)
			}
			rules = append(rules, r.RuleID)
		}
		if len(fams) != 1 {
			exact = false
		}
		if len(rules) > 0 {
			parts = append(parts, "scanner:"+strings.Join(fams, ","), "rule:"+strings.Join(rules, ","))
		}
	}
	parts = append(parts, "state:open,under_investigation,affected")
	return strings.Join(parts, " "), exact
}

// FindingFacts are what a control reads of a finding.
type FindingFacts struct {
	CWEs          []int
	Category      string
	ScannerFamily string
	RuleID        string
	Band          string // the risk band: critical, high, medium, low
}

func bandRank(b string) int {
	switch b {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Breaks says whether an open finding counts against this control: it has one of the weaknesses, or is of one of the
// categories, or was raised by one of the rules, and its band is at least minSeverity. It is the rule the SQL of
// ControlCounts applies to every finding of a tenant, written for one finding; a test holds the two to the same
// answer. A manual control is attested by a person and no finding breaks it.
func (c Control) Breaks(f FindingFacts) bool {
	if c.Manual {
		return false
	}
	band := f.Band
	if band == "" {
		band = "low"
	}
	if bandRank(band) < bandRank(c.MinSeverity) {
		return false
	}
	for _, w := range c.CWEs {
		for _, x := range f.CWEs {
			if w == x {
				return true
			}
		}
	}
	for _, cat := range c.Categories {
		if cat == f.Category {
			return true
		}
	}
	for _, r := range c.Rules {
		if r.ScannerFamily != f.ScannerFamily {
			continue
		}
		if prefix, wild := strings.CutSuffix(r.RuleID, "*"); f.RuleID == prefix || (wild && strings.HasPrefix(f.RuleID, prefix)) {
			return true
		}
	}
	return false
}
