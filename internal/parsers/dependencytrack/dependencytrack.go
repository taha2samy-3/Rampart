// Package dependencytrack parses Dependency-Track findings from FPF exports (FPF 1.0–1.4)
// and direct API responses (/api/v1/finding/project/{uuid}). A streaming walk over findings (D15).
package dependencytrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Dependency-Track FPF and API findings reports.
type Parser struct{}

// NewParser returns a new Dependency-Track parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name identifies the parser implementation.
func (p *Parser) Name() string {
	return "dependency-track-fpf"
}

// Detect scores how likely head is a Dependency-Track findings report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	if strings.Contains(s, `"runs"`) || strings.Contains(s, `"bomFormat"`) || strings.Contains(s, `"spdxVersion"`) {
		return 0
	}

	score := 0
	lowerFilename := strings.ToLower(filename)
	if strings.Contains(lowerFilename, "fpf") || strings.Contains(lowerFilename, "findings-") || strings.Contains(lowerFilename, "dependency-track") {
		score += 35
	}
	if strings.Contains(s, `"findings"`) {
		score += 30
	}
	if strings.Contains(s, `"vulnerability"`) && strings.Contains(s, `"component"`) {
		score += 30
	}
	if strings.Contains(s, `"matrix"`) {
		score += 20
	}
	if strings.Contains(s, `"analyzerIdentity"`) || strings.Contains(s, `"attributedOn"`) {
		score += 15
	}
	return min(score, 100)
}

type findingItem struct {
	Component     componentItem     `json:"component"`
	Vulnerability vulnerabilityItem `json:"vulnerability"`
	Analysis      *analysisItem     `json:"analysis,omitempty"`
	Attribution   *attributionItem  `json:"attribution,omitempty"`
	Matrix        string            `json:"matrix,omitempty"`
}

type componentItem struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Group         string `json:"group,omitempty"`
	Version       string `json:"version"`
	PURL          string `json:"purl"`
	LatestVersion string `json:"latestVersion,omitempty"`
	Project       string `json:"project,omitempty"`
}

type aliasItem struct {
	VulnID string `json:"vulnId"`
	Source string `json:"source,omitempty"`
	CVEID  string `json:"cveId,omitempty"`
	GHSAID string `json:"ghsaId,omitempty"`
}

type cweItem struct {
	CWEID int    `json:"cweId"`
	Name  string `json:"name,omitempty"`
}

type vulnerabilityItem struct {
	UUID           string      `json:"uuid"`
	VulnID         string      `json:"vulnId"`
	Source         string      `json:"source"`
	Aliases        []aliasItem `json:"aliases,omitempty"`
	Title          string      `json:"title,omitempty"`
	SubTitle       string      `json:"subTitle,omitempty"`
	Description    string      `json:"description,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`
	Severity       string      `json:"severity"`
	SeverityRank   int         `json:"severityRank,omitempty"`
	CVSSV2Vector   string      `json:"cvssV2Vector,omitempty"`
	CVSSV3Vector   string      `json:"cvssV3Vector,omitempty"`
	CVSSV4Vector   string      `json:"cvssV4Vector,omitempty"`
	CWEs           []cweItem   `json:"cwes,omitempty"`
}

type analysisItem struct {
	State         string `json:"state"`
	IsSuppressed  bool   `json:"isSuppressed"`
	Justification string `json:"justification,omitempty"`
	Response      string `json:"response,omitempty"`
	Details       string `json:"details,omitempty"`
}

type attributionItem struct {
	AnalyzerIdentity string `json:"analyzerIdentity,omitempty"`
	AttributedOn     int64  `json:"attributedOn,omitempty"`
}

// Parse streams the findings of a Dependency-Track FPF export or API response.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		tok, err := dec.Token()
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("dependency-track: reading initial token: %w", err))
			return
		}

		delim, ok := tok.(json.Delim)
		if !ok {
			yield(domain.RawFinding{}, fmt.Errorf("dependency-track: expected '{' or '[', found %v", tok))
			return
		}

		switch delim {
		case '[':
			// Direct findings array: [ { "component": ..., "vulnerability": ... }, ... ]
			p.parseFindingsArray(ctx, dec, pc, yield)
			_ = parseutil.Expect(dec, ']')

		case '{':
			// FPF container object: { "version": "1.4", "findings": [ ... ] }
			for dec.More() {
				if ctx.Err() != nil {
					return
				}
				keyTok, err := dec.Token()
				if err != nil {
					yield(domain.RawFinding{}, fmt.Errorf("dependency-track: reading object key: %w", err))
					return
				}
				key, ok := keyTok.(string)
				if !ok {
					continue
				}
				if key == "findings" {
					arrTok, err := dec.Token()
					if err != nil || arrTok != json.Delim('[') {
						yield(domain.RawFinding{}, fmt.Errorf("dependency-track: expected '[' for findings, got %v", arrTok))
						return
					}
					if !p.parseFindingsArray(ctx, dec, pc, yield) {
						return
					}
					if err := parseutil.Expect(dec, ']'); err != nil {
						yield(domain.RawFinding{}, fmt.Errorf("dependency-track: closing findings array: %w", err))
						return
					}
				} else {
					if err := parseutil.Skip(dec); err != nil {
						yield(domain.RawFinding{}, fmt.Errorf("dependency-track: skipping key %q: %w", key, err))
						return
					}
				}
			}
			_ = parseutil.Expect(dec, '}')

		default:
			yield(domain.RawFinding{}, fmt.Errorf("dependency-track: unexpected delimiter %v", delim))
		}
	}
}

func (p *Parser) parseFindingsArray(
	ctx context.Context,
	dec *json.Decoder,
	pc domain.ParseContext,
	yield func(domain.RawFinding, error) bool,
) bool {
	idx := 0
	for dec.More() {
		if ctx.Err() != nil {
			return false
		}
		idx++
		var item findingItem
		raw, err := parseutil.Element(dec, &item)
		if err != nil {
			var re *domain.RecordError
			if errors.As(err, &re) && pc.RecordError != nil {
				rec := *re
				if rec.Where == "" {
					rec.Where = fmt.Sprintf("finding %d", idx)
				}
				pc.RecordError(rec)
				continue
			}
			return yield(domain.RawFinding{}, err)
		}

		rf := p.buildRawFinding(item, raw)
		if !yield(rf, nil) {
			return false
		}
	}
	return true
}

func (p *Parser) buildRawFinding(item findingItem, raw json.RawMessage) domain.RawFinding {
	vuln := item.Vulnerability
	comp := item.Component

	ruleID := vuln.VulnID
	if ruleID == "" {
		ruleID = vuln.UUID
	}

	vulnIDs := []string{ruleID}
	for _, alias := range vuln.Aliases {
		if alias.VulnID != "" && alias.VulnID != ruleID {
			vulnIDs = append(vulnIDs, alias.VulnID)
		}
		if alias.CVEID != "" && alias.CVEID != ruleID {
			vulnIDs = append(vulnIDs, alias.CVEID)
		}
		if alias.GHSAID != "" && alias.GHSAID != ruleID {
			vulnIDs = append(vulnIDs, alias.GHSAID)
		}
	}

	title := vuln.Title
	if title == "" {
		compName := comp.Name
		if compName == "" {
			compName = comp.PURL
		}
		if comp.Version != "" {
			compName += "@" + comp.Version
		}
		title = fmt.Sprintf("%s in %s", ruleID, compName)
	}

	cvssVector := vuln.CVSSV3Vector
	if cvssVector == "" {
		cvssVector = vuln.CVSSV4Vector
	}
	if cvssVector == "" {
		cvssVector = vuln.CVSSV2Vector
	}

	var cwes []int
	for _, c := range vuln.CWEs {
		if c.CWEID > 0 {
			cwes = append(cwes, c.CWEID)
		}
	}

	toolRecordID := item.Matrix
	if toolRecordID == "" {
		toolRecordID = fmt.Sprintf("%s:%s", comp.UUID, vuln.UUID)
	}

	rf := domain.RawFinding{
		RuleID:          ruleID,
		RuleName:        vuln.Title,
		RuleDescription: vuln.SubTitle,
		ScannerFamily:   "dependency-track",
		ScannerName:     "Dependency-Track",
		Category:        domain.CategorySCA,
		ToolRecordID:    toolRecordID,
		ToolSeverity:    vuln.Severity,
		Severity:        mapSeverity(vuln.Severity),
		Title:           title,
		Description:     vuln.Description,
		Location: domain.Location{
			Package: parseutil.Package(
				comp.PURL,
				comp.Name,
				comp.Version,
				"", // Fixed version may be populated via recommendation/enrichment
				"",
			),
		},
		CWEs:       cwes,
		VulnIDs:    vulnIDs,
		CVSSVector: cvssVector,
		VEX:        mapAnalysis(item.Analysis, ruleID),
		RawPayload: raw,
	}

	return rf
}

func mapSeverity(toolSeverity string) domain.Severity {
	switch strings.ToUpper(strings.TrimSpace(toolSeverity)) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	case "INFO", "INFORMATIONAL", "UNASSIGNED":
		return domain.SeverityInfo
	default:
		return parseutil.Severity(toolSeverity, 0)
	}
}

func mapAnalysis(a *analysisItem, vulnID string) *domain.VEXStatement {
	if a == nil {
		return nil
	}

	state := strings.ToUpper(strings.TrimSpace(a.State))
	if state == "" || state == "NOT_SET" {
		if a.IsSuppressed {
			return &domain.VEXStatement{
				VulnID:        vulnID,
				State:         domain.StateRiskAccepted,
				Justification: mapJustification(a.Justification),
				Impact:        a.Details,
				Action:        a.Response,
			}
		}
		return nil
	}

	var mappedState domain.FindingState
	switch state {
	case "IN_TRIAGE":
		mappedState = domain.StateUnderInvestigation
	case "EXPLOITABLE":
		mappedState = domain.StateAffected
	case "NOT_AFFECTED":
		mappedState = domain.StateNotAffected
	case "FALSE_POSITIVE":
		mappedState = domain.StateNotAffected
	case "RESOLVED":
		mappedState = domain.StateNotAffected
	default:
		if a.IsSuppressed {
			mappedState = domain.StateRiskAccepted
		} else {
			mappedState = domain.StateOpen
		}
	}

	justification := mapJustification(a.Justification)
	if state == "FALSE_POSITIVE" && justification == "" {
		justification = "vulnerable_code_not_present"
	}

	return &domain.VEXStatement{
		VulnID:        vulnID,
		State:         mappedState,
		Justification: justification,
		Impact:        a.Details,
		Action:        a.Response,
	}
}

func mapJustification(j string) string {
	switch strings.ToUpper(strings.TrimSpace(j)) {
	case "CODE_NOT_PRESENT":
		return "vulnerable_code_not_present"
	case "CODE_NOT_REACHABLE":
		return "vulnerable_code_not_in_execute_path"
	case "REQUIRES_CONFIGURATION", "REQUIRES_DEPENDENCY", "REQUIRES_ENVIRONMENT":
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	case "PROTECTED_BY_COMPILER", "PROTECTED_AT_RUNTIME", "PROTECTED_AT_PERIMETER", "PROTECTED_BY_MITIGATING_CONTROL":
		return "inline_mitigations_already_exist"
	default:
		return strings.ToLower(strings.TrimSpace(j))
	}
}
