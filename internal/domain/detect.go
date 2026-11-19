package domain

import (
	"path/filepath"
	"strings"
)

// DetectProbe is the older, simpler form of a detection test: all the JSON keys, or all the strings, are in the head.
type DetectProbe struct {
	JSONHasKeys []string `json:"jsonHasKeys,omitempty" yaml:"jsonHasKeys,omitempty"`
	Contains    []string `json:"contains,omitempty" yaml:"contains,omitempty"`
}

// DetectRule is one weighted test on the head of a report. It matches when every string of AllOf and at least one of
// AnyOf (each that is given) is in the head. A matching rule adds Weight; one with Return set ends the detection with
// that score (a document that names its own format).
type DetectRule struct {
	AllOf  []string `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	AnyOf  []string `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	Weight int      `json:"weight,omitempty" yaml:"weight,omitempty"`
	Return int      `json:"return,omitempty" yaml:"return,omitempty"`
}

// DetectSpec says how a parser recognises a report: by file name, content type and the head of the document. One scale
// serves every kind of parser (compiled-in, WASM, Lua, SBOM), so a tenant's or a cluster's copy cannot outbid the
// default of the same format by using another scale (docs/34 F11).
//
// The weights of the earlier hand-written scorers are expressed as Rules, so a parser moved out of the binary scores a
// report the same. A spec with no Rules keeps the simple form: a file name adds 50, a content type 50, the first probe
// that matches 60.
type DetectSpec struct {
	Filenames    []string      `json:"filenames,omitempty" yaml:"filenames,omitempty"`
	ContentTypes []string      `json:"contentTypes,omitempty" yaml:"contentTypes,omitempty"`
	Probes       []DetectProbe `json:"probes,omitempty" yaml:"probes,omitempty"`
	Rules        []DetectRule  `json:"rules,omitempty" yaml:"rules,omitempty"`
	// Reject: a head with any of these strings is never this format (the keys of a format another parser reads).
	Reject []string `json:"reject,omitempty" yaml:"reject,omitempty"`
	// FilenameWeight is what a matching file name adds (default 50).
	FilenameWeight int `json:"filenameWeight,omitempty" yaml:"filenameWeight,omitempty"`
	// MinScore: a total below it is 0 (an array of something else must not be taken for this format).
	MinScore int `json:"minScore,omitempty" yaml:"minScore,omitempty"`
}

// Score rates how well a report fits, from 0 (not this format) to 100. The head is the first bytes of the document.
func (d DetectSpec) Score(head []byte, filename, contentType string) int {
	s := string(head)
	for _, r := range d.Reject {
		if r != "" && strings.Contains(s, r) {
			return 0
		}
	}
	for _, r := range d.Rules {
		if r.Return > 0 && r.matches(s) {
			return min(r.Return, 100)
		}
	}
	score := 0
	if filename != "" {
		base := strings.ToLower(filepath.Base(filename))
		for _, pattern := range d.Filenames {
			if ok, _ := filepath.Match(strings.ToLower(pattern), base); ok {
				w := d.FilenameWeight
				if w == 0 {
					w = 50
				}
				score += w
				break
			}
		}
	}
	if contentType != "" {
		lowerCT := strings.ToLower(contentType)
		for _, pattern := range d.ContentTypes {
			lp := strings.ToLower(pattern)
			if ok, _ := filepath.Match(lp, lowerCT); ok || strings.Contains(lowerCT, strings.Trim(lp, "*")) {
				score += 50
				break
			}
		}
	}
	for _, r := range d.Rules {
		if r.Return == 0 && r.matches(s) {
			score += r.Weight
		}
	}
	for _, p := range d.Probes {
		if p.matches(s) {
			score += 60
			break
		}
	}
	if score > 100 {
		score = 100
	}
	if d.MinScore > 0 && score < d.MinScore {
		return 0
	}
	return score
}

func (r DetectRule) matches(head string) bool {
	if len(r.AllOf) == 0 && len(r.AnyOf) == 0 {
		return false
	}
	for _, s := range r.AllOf {
		if !strings.Contains(head, s) {
			return false
		}
	}
	if len(r.AnyOf) > 0 {
		for _, s := range r.AnyOf {
			if strings.Contains(head, s) {
				return true
			}
		}
		return false
	}
	return true
}

func (p DetectProbe) matches(head string) bool {
	if len(p.JSONHasKeys) > 0 {
		all := true
		for _, k := range p.JSONHasKeys {
			if !strings.Contains(head, `"`+k+`"`) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	if len(p.Contains) > 0 {
		all := true
		for _, c := range p.Contains {
			if !strings.Contains(head, c) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
