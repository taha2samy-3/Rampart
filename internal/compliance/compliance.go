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
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	CWEs       []int    `json:"cwes,omitempty"`       // findings with any of these weaknesses count
	Categories []string `json:"categories,omitempty"` // findings of these categories count, and these scans evidence it
	Rank       int      `json:"rank,omitempty"`
}

// Framework is a versioned list of controls.
type Framework struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Source   string    `json:"source"`
	Kind     string    `json:"kind"` // cwe: matched by weakness; category: matched by the kind of scan
	Note     string    `json:"note,omitempty"`
	Controls []Control `json:"controls"`
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
// "not assessed" rather than "clear": no findings from a scan that did not happen prove nothing.
var FamilyCategories = map[string][]string{
	"semgrep": {"sast", "secret"}, "sarif": {"sast"}, "gitleaks": {"secret"}, "trufflehog": {"secret"},
	"trivy": {"sca", "container", "iac", "secret"}, "grype": {"sca", "container"}, "syft": {"sca"},
	"dependency-track": {"sca"}, "zap": {"dast"}, "nuclei": {"dast"}, "checkov": {"iac"}, "kics": {"iac"}, "prowler": {"cspm"},
}

// Status is a control's reading.
type Status string

const (
	StatusOpen        Status = "open"         // findings that bear on it are open
	StatusClear       Status = "clear"        // assessed, and none are open
	StatusNotAssessed Status = "not_assessed" // no scan that could evidence it ran lately
)

// Assessed says whether the control has evidence: some scan of a kind it needs ran. A control matched by
// weakness only needs any code or component scan.
func (c Control) Assessed(scanned map[string]bool) bool {
	need := c.Categories
	if len(need) == 0 {
		need = []string{"sast", "dast", "sca", "container"}
	}
	for _, cat := range need {
		if scanned[cat] {
			return true
		}
	}
	return false
}

// Query is the findings filter that lists what bears on a control, in the grammar of docs/11.
func (c Control) Query() string {
	var parts []string
	if len(c.CWEs) > 0 {
		cw := make([]string, len(c.CWEs))
		for i, n := range c.CWEs {
			cw[i] = fmt.Sprint(n)
		}
		parts = append(parts, "cwe:"+strings.Join(cw, ","))
	} else if len(c.Categories) > 0 {
		parts = append(parts, "category:"+strings.Join(c.Categories, ","))
	}
	parts = append(parts, "state:open,under_investigation,affected")
	return strings.Join(parts, " ")
}
