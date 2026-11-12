package vex

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// Item is the current decision on one vulnerability in one package, as the export states it.
type Item struct {
	Vuln          string
	Purl          string
	State         domain.FindingState
	Justification string
	Impact        string
	Action        string
	At            time.Time
}

// Meta is who writes the document.
type Meta struct {
	ID     string
	Author string
	At     time.Time
}

// openVEXStatus maps Rampart's states to OpenVEX's four (docs/03 section 4). A risk acceptance is a business
// decision, not an exploitability one: to a reader of the document the product is still affected.
func openVEXStatus(it Item) (status, action string, ok bool) {
	switch it.State {
	case domain.StateOpen, domain.StateUnderInvestigation:
		return "under_investigation", "", true
	case domain.StateAffected:
		a := it.Action
		if a == "" {
			a = "Remediation is required."
		}
		return "affected", a, true
	case domain.StateRiskAccepted:
		a := it.Action
		if a == "" {
			a = "Risk accepted: no reason recorded."
		}
		return "affected", a, true
	case domain.StateNotAffected:
		return "not_affected", "", true
	case domain.StateFixed:
		return "fixed", "", true
	}
	return "", "", false // out_of_scope and duplicate say nothing about exploitability
}

// rank decides which of several findings for the same vulnerability and package speaks for it: the most
// worrying state wins, so a document never claims "not affected" while another instance is open.
func rank(s domain.FindingState) int {
	switch s {
	case domain.StateAffected, domain.StateRiskAccepted:
		return 4
	case domain.StateOpen, domain.StateUnderInvestigation:
		return 3
	case domain.StateFixed:
		return 2
	case domain.StateNotAffected:
		return 1
	}
	return 0
}

// Collapse keeps one item per vulnerability and package, drops those with nothing to say, and orders them.
func Collapse(items []Item) []Item {
	best := map[[2]string]Item{}
	for _, it := range items {
		if it.Vuln == "" || it.Purl == "" {
			continue
		}
		if _, _, ok := openVEXStatus(it); !ok {
			continue
		}
		k := [2]string{it.Vuln, it.Purl}
		if cur, ok := best[k]; !ok || rank(it.State) > rank(cur.State) || (rank(it.State) == rank(cur.State) && it.At.After(cur.At)) {
			best[k] = it
		}
	}
	out := make([]Item, 0, len(best))
	for _, it := range best {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vuln != out[j].Vuln {
			return out[i].Vuln < out[j].Vuln
		}
		return out[i].Purl < out[j].Purl
	})
	return out
}

// OpenVEX builds an OpenVEX 0.2 document.
func OpenVEX(m Meta, items []Item) map[string]any {
	stmts := make([]map[string]any, 0, len(items))
	for _, it := range Collapse(items) {
		status, action, _ := openVEXStatus(it)
		s := map[string]any{
			"vulnerability": map[string]any{"name": it.Vuln},
			"products":      []map[string]any{{"@id": it.Purl, "identifiers": map[string]any{"purl": it.Purl}}},
			"status":        status,
		}
		if !it.At.IsZero() {
			s["timestamp"] = it.At.UTC().Format(time.RFC3339)
		}
		if status == "not_affected" {
			if it.Justification != "" {
				s["justification"] = it.Justification
			}
			if it.Impact != "" {
				s["impact_statement"] = it.Impact
			}
		}
		if action != "" {
			s["action_statement"] = action
		}
		stmts = append(stmts, s)
	}
	return map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0", "@id": m.ID, "author": m.Author, "role": "Security platform",
		"timestamp": m.At.UTC().Format(time.RFC3339), "version": 1, "statements": stmts,
	}
}

var cdxState = map[domain.FindingState]string{
	domain.StateOpen: "in_triage", domain.StateUnderInvestigation: "in_triage", domain.StateAffected: "exploitable",
	domain.StateRiskAccepted: "exploitable", domain.StateNotAffected: "not_affected", domain.StateFixed: "resolved",
}

var cdxJustificationOut = map[string]string{
	"component_not_present":                             "code_not_present",
	"vulnerable_code_not_present":                       "code_not_present",
	"vulnerable_code_not_in_execute_path":               "code_not_reachable",
	"vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
	"inline_mitigations_already_exist":                  "protected_by_mitigating_control",
}

// CycloneDX builds a CycloneDX 1.6 VEX document. The five OpenVEX justifications do not map one to one onto
// CycloneDX's nine, so the original is written as a property and read back by Parse.
func CycloneDX(m Meta, items []Item) map[string]any {
	collapsed := Collapse(items)
	components := make([]map[string]any, 0, len(collapsed))
	seen := map[string]bool{}
	vulns := make([]map[string]any, 0, len(collapsed))
	for _, it := range collapsed {
		if !seen[it.Purl] {
			seen[it.Purl] = true
			components = append(components, map[string]any{"type": "library", "bom-ref": it.Purl, "purl": it.Purl})
		}
		analysis := map[string]any{"state": cdxState[it.State]}
		var props []map[string]any
		if it.State == domain.StateNotAffected {
			if j := cdxJustificationOut[it.Justification]; j != "" {
				analysis["justification"] = j
			}
			if it.Justification != "" {
				props = append(props, map[string]any{"name": propJustification, "value": it.Justification})
			}
		}
		if it.State == domain.StateAffected || it.State == domain.StateRiskAccepted {
			analysis["response"] = []string{"will_not_fix"}
			if it.State == domain.StateAffected {
				analysis["response"] = []string{"update"}
			}
			if it.Action != "" {
				props = append(props, map[string]any{"name": propAction, "value": it.Action})
			}
		}
		if it.Impact != "" {
			analysis["detail"] = it.Impact
		}
		if !it.At.IsZero() {
			analysis["lastUpdated"] = it.At.UTC().Format(time.RFC3339)
		}
		v := map[string]any{"id": it.Vuln, "analysis": analysis, "affects": []map[string]any{{"ref": it.Purl}}}
		if len(props) > 0 {
			v["properties"] = props
		}
		vulns = append(vulns, v)
	}
	return map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": fmt.Sprintf("urn:uuid:%s", uuid.NewSHA1(uuid.NameSpaceURL, []byte(m.ID))),
		"metadata":     map[string]any{"timestamp": m.At.UTC().Format(time.RFC3339), "authors": []map[string]any{{"name": m.Author}}},
		"components":   components, "vulnerabilities": vulns,
	}
}
