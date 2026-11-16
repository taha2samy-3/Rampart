package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidFramework wraps every reason a ComplianceFramework is refused.
var ErrInvalidFramework = errors.New("compliance framework")

// FrameworkSpec is the spec of a ComplianceFramework (one tenant) or a ClusterComplianceFramework (every tenant):
// a framework that is not built in, described as data (docs/16 D102). The built-in frameworks are the same shape.
//
//	spec:
//	  displayName: ACME secure coding policy
//	  version: "2026.1"
//	  source: https://wiki.acme.example/secpol
//	  appliesTo: {complianceScope: pci}       # optional: only applications that list "pci"
//	  evidenceWindowDays: 30
//	  controls:
//	    - id: SC-1
//	      name: No hard-coded credentials
//	      match: {categories: [secret]}
//	    - id: SC-2
//	      name: No critical or high injection flaws
//	      match: {cwes: [77, 78, 79, 89], minSeverity: high}
//	      evidence: {categories: [sast, dast]}
//	    - id: SC-3
//	      name: A threat model is reviewed for each release
//	      manual: true
type FrameworkSpec struct {
	DisplayName        string        `json:"displayName"`
	Version            string        `json:"version"`
	Source             string        `json:"source,omitempty"`
	Description        string        `json:"description,omitempty"`
	Note               string        `json:"note,omitempty"`
	AppliesTo          *AppliesTo    `json:"appliesTo,omitempty"`
	EvidenceWindowDays int           `json:"evidenceWindowDays,omitempty"`
	Controls           []ControlSpec `json:"controls"`
}

// AppliesTo narrows a framework to the applications whose Application.complianceScope lists the scope. Without it
// the framework reads every application of the tenant.
type AppliesTo struct {
	ComplianceScope string `json:"complianceScope"`
}

// ControlSpec is one requirement. It is either matched to findings (match) or attested by a person (manual).
type ControlSpec struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Match       *MatchSpec    `json:"match,omitempty"`
	Evidence    *EvidenceSpec `json:"evidence,omitempty"`
	Manual      bool          `json:"manual,omitempty"`
}

// MatchSpec says which open findings break the control. A finding counts when it has one of the CWEs, or is of
// one of the categories, or was raised by one of the rules; then, when minSeverity is set, only if its risk band is
// at least that.
type MatchSpec struct {
	CWEs        []int       `json:"cwes,omitempty"`
	Categories  []string    `json:"categories,omitempty"`
	Rules       []RuleMatch `json:"rules,omitempty"`
	MinSeverity string      `json:"minSeverity,omitempty"`
}

// RuleMatch is a scanner's own rule. RuleID may end in * to take every rule with that prefix.
type RuleMatch struct {
	ScannerFamily string `json:"scannerFamily"`
	RuleID        string `json:"ruleId"`
}

// EvidenceSpec says which scans must have run for the control to be read at all. Without it: the match's
// categories; for a control matched by CWE only, a code scan (SAST or DAST); for rules, their scanners.
type EvidenceSpec struct {
	Categories []string `json:"categories,omitempty"`
}

var (
	controlIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	familyRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,63}$`)
	ruleRe      = regexp.MustCompile(`^[^\s*]{1,200}\*?$`)
)

// Bands a minSeverity may name, worst first.
var Bands = []string{"critical", "high", "medium", "low"}

// ParseFrameworkSpec decodes and checks a framework strictly: a misspelled field is refused, not ignored, so a
// control can never silently match nothing.
func ParseFrameworkSpec(raw []byte) (*FrameworkSpec, error) {
	var s FrameworkSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFramework, err)
	}
	return &s, s.Validate()
}

// Validate says what is wrong, naming the control.
func (s *FrameworkSpec) Validate() error {
	bad := func(f string, a ...any) error {
		return fmt.Errorf("%w: "+f, append([]any{ErrInvalidFramework}, a...)...)
	}
	if strings.TrimSpace(s.DisplayName) == "" {
		return bad("displayName is required")
	}
	if strings.TrimSpace(s.Version) == "" {
		return bad("version is required, so a report says which version of the framework it read")
	}
	if s.EvidenceWindowDays < 0 || s.EvidenceWindowDays > 366 {
		return bad("evidenceWindowDays is between 1 and 366 (default 30)")
	}
	if s.AppliesTo != nil && !familyRe.MatchString(s.AppliesTo.ComplianceScope) {
		return bad("appliesTo.complianceScope %q: lower-case letters, digits and - . _ :", s.AppliesTo.ComplianceScope)
	}
	if len(s.Controls) == 0 {
		return bad("a framework needs at least one control")
	}
	if len(s.Controls) > 1000 {
		return bad("a framework has at most 1000 controls")
	}
	seen := map[string]bool{}
	for _, c := range s.Controls {
		where := fmt.Sprintf("control %q", c.ID)
		if !controlIDRe.MatchString(c.ID) || seen[c.ID] {
			return bad("%s: an id is letters, digits and . _ : -, unique in the framework", where)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Name) == "" {
			return bad("%s: name is required", where)
		}
		if c.Manual {
			if c.Match != nil || c.Evidence != nil {
				return bad("%s: a manual control is attested by a person; it has no match or evidence", where)
			}
			continue
		}
		m := c.Match
		if m == nil || (len(m.CWEs) == 0 && len(m.Categories) == 0 && len(m.Rules) == 0) {
			return bad("%s: give match.cwes, match.categories or match.rules, or set manual: true", where)
		}
		for _, n := range m.CWEs {
			if n <= 0 || n > 10000 {
				return bad("%s: CWE %d is not a CWE id", where, n)
			}
		}
		for _, cat := range m.Categories {
			if !knownCategory[cat] {
				return bad("%s: unknown category %q (one of %s)", where, cat, categoryList())
			}
		}
		for _, r := range m.Rules {
			if !familyRe.MatchString(r.ScannerFamily) || !ruleRe.MatchString(r.RuleID) {
				return bad("%s: a rule is {scannerFamily, ruleId}; ruleId may end in *", where)
			}
		}
		if m.MinSeverity != "" && !contains(Bands, m.MinSeverity) {
			return bad("%s: minSeverity is critical, high, medium or low", where)
		}
		if c.Evidence != nil {
			if len(c.Evidence.Categories) == 0 {
				return bad("%s: evidence.categories is empty; remove evidence to use the default", where)
			}
			for _, cat := range c.Evidence.Categories {
				if !knownCategory[cat] {
					return bad("%s: unknown evidence category %q (one of %s)", where, cat, categoryList())
				}
			}
		}
	}
	return nil
}

// Framework turns a validated spec into the framework the evaluation reads. origin is "cluster" or "tenant".
func (s *FrameworkSpec) Framework(id, origin string) Framework {
	f := Framework{ID: id, Name: s.DisplayName, Version: s.Version, Source: s.Source, Note: s.Note, Kind: "custom", Origin: origin,
		WindowDays: s.EvidenceWindowDays}
	if s.AppliesTo != nil {
		f.Scope = s.AppliesTo.ComplianceScope
	}
	for _, c := range s.Controls {
		ctl := Control{ID: c.ID, Name: c.Name, Description: c.Description, Manual: c.Manual}
		if c.Match != nil {
			ctl.CWEs, ctl.Categories, ctl.Rules, ctl.MinSeverity = c.Match.CWEs, c.Match.Categories, c.Match.Rules, c.Match.MinSeverity
		}
		if c.Evidence != nil {
			ctl.Evidence = c.Evidence.Categories
		}
		f.Controls = append(f.Controls, ctl)
	}
	return f
}

func categoryList() string {
	out := make([]string, 0, len(knownCategory))
	for _, c := range []string{"sast", "sca", "secret", "iac", "container", "dast", "cspm", "compliance", "license", "supply_chain"} {
		if knownCategory[c] {
			out = append(out, c)
		}
	}
	return strings.Join(out, ", ")
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
