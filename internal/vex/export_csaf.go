package vex

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"rampart/internal/domain"
)

// justificationToCSAFFlag maps OpenVEX justifications to CSAF 2.0 standard flag labels.
func justificationToCSAFFlag(just string) string {
	switch just {
	case "component_not_present":
		return "component_not_present"
	case "inline_mitigations_already_exist":
		return "inline_mitigations_already_exist"
	case "vulnerable_code_not_present":
		return "vulnerable_code_not_present"
	case "code_not_reachable", "vulnerable_code_not_in_execute_path":
		return "vulnerable_code_not_in_execute_path"
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	default:
		return "component_not_present"
	}
}

// CSAF builds a CSAF 2.0 VEX document from decisions (OASIS standard ISO/IEC 20153:2025).
func CSAF(m Meta, items []Item) map[string]any {
	collapsed := Collapse(items)

	// Collect unique PURLs and map to product IDs
	purlToID := make(map[string]string)
	var productNames []map[string]any
	idx := 1
	for _, it := range collapsed {
		if _, ok := purlToID[it.Purl]; !ok {
			pid := fmt.Sprintf("CSAFPID-%04d", idx)
			idx++
			purlToID[it.Purl] = pid
			productNames = append(productNames, map[string]any{
				"product_id": pid,
				"name":       it.Purl,
				"product_identification_helper": map[string]any{
					"purl": it.Purl,
				},
			})
		}
	}

	// Group items by vulnerability
	type vulnGroup struct {
		vuln  string
		items []Item
	}
	grouped := make(map[string][]Item)
	for _, it := range collapsed {
		grouped[it.Vuln] = append(grouped[it.Vuln], it)
	}

	var vulnKeys []string
	for v := range grouped {
		vulnKeys = append(vulnKeys, v)
	}
	sort.Strings(vulnKeys)

	var vulns []map[string]any
	for _, vKey := range vulnKeys {
		vItems := grouped[vKey]
		vEntry := map[string]any{}
		if strings.HasPrefix(strings.ToUpper(vKey), "CVE-") {
			vEntry["cve"] = vKey
		} else {
			vEntry["ids"] = []map[string]any{
				{"system_name": "Rampart Advisory", "text": vKey},
			}
		}

		knownNotAffected := []string{}
		knownAffected := []string{}
		fixed := []string{}
		underInvestigation := []string{}

		var flags []map[string]any
		var threats []map[string]any
		var remediations []map[string]any

		for _, it := range vItems {
			pid := purlToID[it.Purl]
			switch it.State {
			case domain.StateNotAffected:
				knownNotAffected = append(knownNotAffected, pid)
				if it.Justification != "" {
					flags = append(flags, map[string]any{
						"label":       justificationToCSAFFlag(it.Justification),
						"product_ids": []string{pid},
					})
				}
				if it.Impact != "" {
					threats = append(threats, map[string]any{
						"category":    "impact",
						"details":     it.Impact,
						"product_ids": []string{pid},
					})
				}
			case domain.StateAffected, domain.StateRiskAccepted:
				knownAffected = append(knownAffected, pid)
				action := it.Action
				if action == "" {
					if it.State == domain.StateRiskAccepted {
						action = "Risk accepted: monitored in production."
					} else {
						action = "Remediation is required."
					}
				}
				remediations = append(remediations, map[string]any{
					"category":    "mitigation",
					"details":     action,
					"product_ids": []string{pid},
				})
			case domain.StateFixed:
				fixed = append(fixed, pid)
			case domain.StateOpen, domain.StateUnderInvestigation:
				underInvestigation = append(underInvestigation, pid)
			}
		}

		status := map[string]any{}
		if len(knownNotAffected) > 0 {
			status["known_not_affected"] = knownNotAffected
		}
		if len(knownAffected) > 0 {
			status["known_affected"] = knownAffected
		}
		if len(fixed) > 0 {
			status["fixed"] = fixed
		}
		if len(underInvestigation) > 0 {
			status["under_investigation"] = underInvestigation
		}
		vEntry["product_status"] = status

		if len(flags) > 0 {
			vEntry["flags"] = flags
		}
		if len(threats) > 0 {
			vEntry["threats"] = threats
		}
		if len(remediations) > 0 {
			vEntry["remediations"] = remediations
		}

		vulns = append(vulns, vEntry)
	}

	ts := m.At.UTC().Format(time.RFC3339)
	return map[string]any{
		"document": map[string]any{
			"category":     "csaf_vex",
			"csaf_version": "2.0",
			"title":        fmt.Sprintf("VEX Statement for %s", m.ID),
			"publisher": map[string]any{
				"category":  "vendor",
				"name":      m.Author,
				"namespace": "https://rampart.aspm.dev",
			},
			"tracking": map[string]any{
				"current_release_date": ts,
				"id":                   m.ID,
				"initial_release_date": ts,
				"status":               "final",
				"version":              "1",
			},
		},
		"product_tree": map[string]any{
			"full_product_names": productNames,
		},
		"vulnerabilities": vulns,
	}
}
