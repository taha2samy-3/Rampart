// Package vex reads and writes VEX documents: OpenVEX 0.2 and CycloneDX VEX (docs/05 section 7, docs/16 D47).
// A VEX document says, per vulnerability and product, whether the product is affected. Importing one decides
// findings; it never creates one.
package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rampart/internal/domain"
)

// Statement is one assertion, in the terms of Rampart: which vulnerability (an id and its aliases), which
// packages, and the state, with the justification in the five OpenVEX words.
type Statement struct {
	Vulns         []string
	Purls         []string // package URLs; a purl with a version matches that version only
	State         domain.FindingState
	Justification string
	Impact        string
	Action        string
	At            time.Time
	// Problem says why the statement cannot be applied (an unknown status, a missing justification). It is
	// reported to the caller; the rest of the document still goes through.
	Problem string
}

// Document is a parsed VEX document.
type Document struct {
	Format     string // openvex | cyclonedx
	ID         string
	Author     string
	At         time.Time
	Statements []Statement
}

// ErrUnknownFormat is returned for JSON that is neither OpenVEX nor CycloneDX.
var ErrUnknownFormat = errors.New("the document is not OpenVEX or CycloneDX VEX")

// MaxDocument is the largest document accepted.
const MaxDocument = 16 << 20

// Parse reads a VEX document of either format.
func Parse(data []byte) (*Document, error) {
	var probe struct {
		Context   string          `json:"@context"`
		BOMFormat string          `json:"bomFormat"`
		Vulns     json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("the document is not valid JSON: %w", err)
	}
	switch {
	case strings.Contains(probe.Context, "openvex"):
		return parseOpenVEX(data)
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDX(data)
	}
	return nil, ErrUnknownFormat
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- OpenVEX -------------------------------------------------------------------------------------------------

// product is an OpenVEX product: a bare string (0.1) or an object (0.2) with identifiers and subcomponents.
type product struct {
	ID            string
	Purl          string
	Subcomponents []product
}

func (p *product) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		p.ID, p.Purl = s, purlOf(s)
		return nil
	}
	var o struct {
		ID          string `json:"@id"`
		Identifiers struct {
			Purl string `json:"purl"`
		} `json:"identifiers"`
		Subcomponents []product `json:"subcomponents"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	p.ID, p.Subcomponents = o.ID, o.Subcomponents
	p.Purl = o.Identifiers.Purl
	if p.Purl == "" {
		p.Purl = purlOf(o.ID)
	}
	return nil
}

func purlOf(s string) string {
	if strings.HasPrefix(s, "pkg:") {
		return s
	}
	return ""
}

func parseOpenVEX(data []byte) (*Document, error) {
	var in struct {
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Vulnerability struct {
				ID      string   `json:"@id"`
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products        []product `json:"products"`
			Status          string    `json:"status"`
			Justification   string    `json:"justification"`
			ImpactStatement string    `json:"impact_statement"`
			ActionStatement string    `json:"action_statement"`
			Timestamp       string    `json:"timestamp"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("the OpenVEX document could not be read: %w", err)
	}
	doc := &Document{Format: "openvex", ID: in.ID, Author: in.Author, At: parseTime(in.Timestamp)}
	for _, s := range in.Statements {
		st := Statement{
			Vulns:         uniq(append([]string{s.Vulnerability.Name, s.Vulnerability.ID}, s.Vulnerability.Aliases...)),
			Justification: s.Justification, Impact: s.ImpactStatement, Action: s.ActionStatement, At: parseTime(s.Timestamp),
		}
		if st.At.IsZero() {
			st.At = doc.At
		}
		var purls []string
		for _, p := range s.Products {
			if len(p.Subcomponents) > 0 { // subcomponents narrow the statement to those packages
				for _, sc := range p.Subcomponents {
					purls = append(purls, sc.Purl)
				}
			} else {
				purls = append(purls, p.Purl)
			}
		}
		st.Purls = uniq(purls)
		switch s.Status {
		case "not_affected":
			st.State = domain.StateNotAffected
		case "affected":
			st.State = domain.StateAffected
		case "fixed":
			st.State = domain.StateFixed
		case "under_investigation":
			st.State = domain.StateUnderInvestigation
		default:
			st.Problem = fmt.Sprintf("the status %q is not an OpenVEX status", s.Status)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// ---- CycloneDX -----------------------------------------------------------------------------------------------

// cdxJustification maps CycloneDX justifications to the five OpenVEX words. The `requires_*` ones say the
// vulnerable code needs a condition that does not hold, which is the closest word; the export keeps the original
// in a property so a round trip loses nothing.
var cdxJustification = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_dependency":             "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_by_compiler":           "inline_mitigations_already_exist",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_at_perimeter":          "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

// Property names Rampart writes so its own export reads back exactly.
const (
	propJustification = "rampart:justification"
	propAction        = "rampart:action"
)

func parseCycloneDX(data []byte) (*Document, error) {
	var in struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Authors   []struct {
				Name string `json:"name"`
			} `json:"authors"`
		} `json:"metadata"`
		Components []struct {
			Ref  string `json:"bom-ref"`
			Purl string `json:"purl"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
				Detail        string   `json:"detail"`
				FirstIssued   string   `json:"firstIssued"`
				LastUpdated   string   `json:"lastUpdated"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&in); err != nil {
		return nil, fmt.Errorf("the CycloneDX document could not be read: %w", err)
	}
	doc := &Document{Format: "cyclonedx", ID: in.SerialNumber, At: parseTime(in.Metadata.Timestamp)}
	if len(in.Metadata.Authors) > 0 {
		doc.Author = in.Metadata.Authors[0].Name
	}
	refPurl := map[string]string{}
	for _, c := range in.Components {
		if c.Ref != "" && c.Purl != "" {
			refPurl[c.Ref] = c.Purl
		}
	}
	for _, v := range in.Vulnerabilities {
		if v.Analysis.State == "" { // a vulnerability listed with no analysis is a VDR entry, not a VEX statement
			continue
		}
		st := Statement{Vulns: uniq([]string{v.ID}), Impact: v.Analysis.Detail, At: parseTime(firstNonEmpty(v.Analysis.LastUpdated, v.Analysis.FirstIssued))}
		if st.At.IsZero() {
			st.At = doc.At
		}
		var purls []string
		for _, a := range v.Affects {
			if p, ok := refPurl[a.Ref]; ok {
				purls = append(purls, p)
			} else {
				purls = append(purls, purlOf(a.Ref))
			}
		}
		st.Purls = uniq(purls)
		var own struct{ justification, action string }
		for _, p := range v.Properties {
			switch p.Name {
			case propJustification:
				own.justification = p.Value
			case propAction:
				own.action = p.Value
			}
		}
		st.Action = own.action
		switch v.Analysis.State {
		case "not_affected", "false_positive":
			st.State = domain.StateNotAffected
			st.Justification = own.justification
			if st.Justification == "" {
				st.Justification = cdxJustification[v.Analysis.Justification]
			}
			if st.Justification == "" && v.Analysis.State == "false_positive" {
				st.Justification = "vulnerable_code_not_present"
			}
			if st.Justification == "" {
				st.Problem = "not_affected needs a justification, and the document gives none Rampart knows"
			}
		case "exploitable":
			st.State = domain.StateAffected
			if st.Action == "" && len(v.Analysis.Response) > 0 {
				st.Action = strings.Join(v.Analysis.Response, ", ")
			}
		case "resolved", "resolved_with_pedigree":
			st.State = domain.StateFixed
		case "in_triage":
			st.State = domain.StateUnderInvestigation
		default:
			st.Problem = fmt.Sprintf("the analysis state %q is not a CycloneDX state", v.Analysis.State)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
