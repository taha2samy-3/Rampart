package vex

import (
	"encoding/json"
	"fmt"
	"strings"

	"rampart/internal/domain"
)

// csafDoc defines the schema elements of CSAF 2.0 (OASIS standard) relevant for VEX.
type csafDoc struct {
	Document struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			CurrentReleaseDate string `json:"current_release_date"`
			InitialReleaseDate string `json:"initial_release_date"`
		} `json:"tracking"`
		Publisher struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"publisher"`
	} `json:"document"`
	ProductTree struct {
		FullProductNames []csafProductName `json:"full_product_names"`
		Relationships    []struct {
			FullProductName csafProductName `json:"full_product_name"`
		} `json:"relationships"`
		Branches []csafBranch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafProductName struct {
	ProductID                  string `json:"product_id"`
	Name                       string `json:"name"`
	ProductIdentificationHelper struct {
		Purl string `json:"purl"`
		CPE  string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Category string            `json:"category"`
	Name     string            `json:"name"`
	Product  *csafProductName  `json:"product"`
	Branches []csafBranch      `json:"branches"`
}

type csafVulnerability struct {
	CVE string `json:"cve"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	ProductStatus struct {
		KnownNotAffected   []string `json:"known_not_affected"`
		KnownAffected      []string `json:"known_affected"`
		Fixed              []string `json:"fixed"`
		UnderInvestigation []string `json:"under_investigation"`
		Recommended        []string `json:"recommended"`
	} `json:"product_status"`
	Threats []struct {
		Category   string   `json:"category"`
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
	} `json:"threats"`
	Flags []struct {
		Label      string   `json:"label"`
		Date       string   `json:"date"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags"`
	Remediations []struct {
		Category   string   `json:"category"`
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
		Date       string   `json:"date"`
	} `json:"remediations"`
	Notes []struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Text     string `json:"text"`
	} `json:"notes"`
	ReleaseDate string `json:"release_date"`
}

// collectBranches recurses through CSAF product branches to find products with PURLs.
func collectBranches(branches []csafBranch, pMap map[string]string) {
	for _, b := range branches {
		if b.Product != nil && b.Product.ProductID != "" {
			purl := b.Product.ProductIdentificationHelper.Purl
			if purl == "" {
				purl = purlOf(b.Product.ProductID)
			}
			if purl == "" {
				purl = purlOf(b.Product.Name)
			}
			pMap[b.Product.ProductID] = purl
		}
		if len(b.Branches) > 0 {
			collectBranches(b.Branches, pMap)
		}
	}
}

// csafFlagToJustification maps CSAF 2.0 flag labels to OpenVEX standard justifications.
func csafFlagToJustification(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "component_not_present":
		return "component_not_present"
	case "inline_mitigations_already_exist":
		return "inline_mitigations_already_exist"
	case "vulnerable_code_not_present":
		return "vulnerable_code_not_present"
	case "vulnerable_code_not_in_execute_path", "code_not_reachable":
		return "vulnerable_code_not_in_execute_path"
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	default:
		return label
	}
}

// parseCSAF decodes a CSAF 2.0 VEX document.
func parseCSAF(data []byte) (*Document, error) {
	var in csafDoc
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("the CSAF document is malformed: %w", err)
	}

	doc := &Document{
		Format: "csaf",
		ID:     in.Document.Tracking.ID,
		Author: in.Document.Publisher.Name,
		At:     parseTime(in.Document.Tracking.CurrentReleaseDate),
	}
	if doc.At.IsZero() {
		doc.At = parseTime(in.Document.Tracking.InitialReleaseDate)
	}

	// Build product_id -> purl map
	pMap := make(map[string]string)
	for _, p := range in.ProductTree.FullProductNames {
		purl := p.ProductIdentificationHelper.Purl
		if purl == "" {
			purl = purlOf(p.ProductID)
		}
		if purl == "" {
			purl = purlOf(p.Name)
		}
		pMap[p.ProductID] = purl
	}
	for _, r := range in.ProductTree.Relationships {
		p := r.FullProductName
		purl := p.ProductIdentificationHelper.Purl
		if purl == "" {
			purl = purlOf(p.ProductID)
		}
		if purl == "" {
			purl = purlOf(p.Name)
		}
		pMap[p.ProductID] = purl
	}
	collectBranches(in.ProductTree.Branches, pMap)

	for _, v := range in.Vulnerabilities {
		vulns := []string{}
		if v.CVE != "" {
			vulns = append(vulns, v.CVE)
		}
		for _, id := range v.IDs {
			if id.Text != "" {
				vulns = append(vulns, id.Text)
			}
		}
		vulns = uniq(vulns)
		if len(vulns) == 0 {
			continue
		}

		vTime := parseTime(v.ReleaseDate)
		if vTime.IsZero() {
			vTime = doc.At
		}

		// Process known_not_affected
		for _, pid := range v.ProductStatus.KnownNotAffected {
			purl := pMap[pid]
			if purl == "" {
				purl = purlOf(pid)
			}
			purls := []string{}
			if purl != "" {
				purls = []string{purl}
			}

			// Find justification from flags
			var just string
			for _, f := range v.Flags {
				for _, fpid := range f.ProductIDs {
					if fpid == pid {
						just = csafFlagToJustification(f.Label)
						break
					}
				}
				if just != "" {
					break
				}
			}

			// Find impact statement from threats
			var impact string
			for _, t := range v.Threats {
				if strings.EqualFold(t.Category, "impact") {
					for _, tpid := range t.ProductIDs {
						if tpid == pid {
							impact = t.Details
							break
						}
					}
				}
				if impact != "" {
					break
				}
			}

			doc.Statements = append(doc.Statements, Statement{
				Vulns:         vulns,
				Purls:         purls,
				State:         domain.StateNotAffected,
				Justification: just,
				Impact:        impact,
				At:            vTime,
			})
		}

		// Process known_affected
		for _, pid := range v.ProductStatus.KnownAffected {
			purl := pMap[pid]
			if purl == "" {
				purl = purlOf(pid)
			}
			purls := []string{}
			if purl != "" {
				purls = []string{purl}
			}

			var action string
			for _, r := range v.Remediations {
				for _, rpid := range r.ProductIDs {
					if rpid == pid {
						action = r.Details
						break
					}
				}
				if action != "" {
					break
				}
			}

			doc.Statements = append(doc.Statements, Statement{
				Vulns:  vulns,
				Purls:  purls,
				State:  domain.StateAffected,
				Action: action,
				At:     vTime,
			})
		}

		// Process fixed
		for _, pid := range v.ProductStatus.Fixed {
			purl := pMap[pid]
			if purl == "" {
				purl = purlOf(pid)
			}
			purls := []string{}
			if purl != "" {
				purls = []string{purl}
			}

			doc.Statements = append(doc.Statements, Statement{
				Vulns: vulns,
				Purls: purls,
				State: domain.StateFixed,
				At:    vTime,
			})
		}

		// Process under_investigation
		for _, pid := range v.ProductStatus.UnderInvestigation {
			purl := pMap[pid]
			if purl == "" {
				purl = purlOf(pid)
			}
			purls := []string{}
			if purl != "" {
				purls = []string{purl}
			}

			doc.Statements = append(doc.Statements, Statement{
				Vulns: vulns,
				Purls: purls,
				State: domain.StateUnderInvestigation,
				At:    vTime,
			})
		}
	}

	return doc, nil
}
