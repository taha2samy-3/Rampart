package openvex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// Parser parses OpenVEX triage documents (docs/05 §1 & §7).
type Parser struct{}

// NewParser creates a new OpenVEX parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the identifier of this parser.
func (p *Parser) Name() string {
	return "openvex"
}

// Detect checks if the document header indicates an OpenVEX document.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	score := 0
	lowerName := strings.ToLower(filename)
	if strings.Contains(lowerName, "openvex") || strings.HasSuffix(lowerName, ".vex.json") || strings.HasSuffix(lowerName, ".vex") {
		score += 50
	}
	if strings.Contains(contentType, "openvex") {
		score += 50
	}

	headStr := string(head)
	if strings.Contains(headStr, "openvex.dev") {
		score += 70
	}
	if strings.Contains(headStr, `"statements"`) && strings.Contains(headStr, `"vulnerability"`) {
		score += 40
	}

	if score > 100 {
		return 100
	}
	return score
}

// Parse extracts statements as RawFindings carrying VEXStatement payloads.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		var doc openVEXDocument
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("openvex: failed to decode document: %w", err))
			return
		}

		for _, stmt := range doc.Statements {
			if ctx.Err() != nil {
				return
			}

			vulnID := stmt.Vulnerability.Name
			if vulnID == "" {
				vulnID = stmt.Vulnerability.ID
			}

			state := domain.FindingState(stmt.Status)
			if !state.IsValid() {
				// Normalize openvex status strings to domain states
				switch stmt.Status {
				case "not_affected":
					state = domain.StateNotAffected
				case "affected":
					state = domain.StateAffected
				case "under_investigation":
					state = domain.StateUnderInvestigation
				case "fixed":
					state = domain.StateFixed
				default:
					state = domain.StateOpen
				}
			}

			// If products are specified, create a finding for each
			if len(stmt.Products) > 0 {
				for _, prod := range stmt.Products {
					purl := prod
					purlBase := purl
					if idx := strings.Index(purl, "@"); idx != -1 {
						purlBase = purl[:idx]
					}

					loc := domain.Location{
						Package: &domain.PackageLocation{
							Purl:     purl,
							PurlBase: purlBase,
						},
					}

					rawBytes, _ := json.Marshal(stmt)

					rf := domain.RawFinding{
						ScannerFamily: "openvex",
						ScannerName:   "openvex",
						Category:      domain.CategorySCA,
						RuleID:        vulnID,
						Title:         normalize.NFC(fmt.Sprintf("VEX Statement for %s", vulnID)),
						Description:   normalize.NFC(stmt.ImpactStatement),
						ToolSeverity:  "info",
						Severity:      domain.SeverityInfo,
						Location:      loc,
						VulnIDs:       []string{vulnID},
						VEX: &domain.VEXStatement{
							StatementID:   domain.NewID(),
							VulnID:        vulnID,
							State:         state,
							Justification: stmt.Justification,
							Impact:        stmt.ImpactStatement,
							Remediation:   stmt.Remediation,
							Action:        stmt.ActionStatement,
						},
						RawPayload: rawBytes,
					}

					if !yield(rf, nil) {
						return
					}
				}
			} else {
				// Statement without specific products
				rawBytes, _ := json.Marshal(stmt)
				rf := domain.RawFinding{
					ScannerFamily: "openvex",
					ScannerName:   "openvex",
					Category:      domain.CategorySCA,
					RuleID:        vulnID,
					Title:         normalize.NFC(fmt.Sprintf("VEX Statement for %s", vulnID)),
					Description:   normalize.NFC(stmt.ImpactStatement),
					ToolSeverity:  "info",
					Severity:      domain.SeverityInfo,
					VulnIDs:       []string{vulnID},
					VEX: &domain.VEXStatement{
						StatementID:   domain.NewID(),
						VulnID:        vulnID,
						State:         state,
						Justification: stmt.Justification,
						Impact:        stmt.ImpactStatement,
						Remediation:   stmt.Remediation,
						Action:        stmt.ActionStatement,
					},
					RawPayload: rawBytes,
				}

				if !yield(rf, nil) {
					return
				}
			}
		}
	}
}

type openVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
		ID   string `json:"@id"`
	} `json:"vulnerability"`
	Products        []string `json:"products"`
	Status          string   `json:"status"`
	Justification   string   `json:"justification"`
	ImpactStatement string   `json:"impact_statement"`
	ActionStatement string   `json:"action_statement"`
	Remediation     string   `json:"remediation"`
}
