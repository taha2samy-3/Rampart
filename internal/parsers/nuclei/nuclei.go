// Package nuclei parses ProjectDiscovery Nuclei JSONL reports (docs/16 D15, docs/21 §5.5).
package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
)

// Parser reads Nuclei JSONL reports.
type Parser struct{}

// NewParser returns a Nuclei parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "nuclei-jsonl" }

// Detect scores how likely head is a Nuclei JSON lines report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"template-id"`) || strings.Contains(s, `"template_id"`) {
		score += 45
	}
	if strings.Contains(s, `"matched-at"`) || strings.Contains(s, `"matched_at"`) {
		score += 35
	}
	if strings.Contains(s, `"extracted-results"`) || strings.Contains(s, `"curl-command"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "nuclei") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type nucleiFinding struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Author         any    `json:"author"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Remediation    string `json:"remediation"`
		Reference      any    `json:"reference"`
		Classification struct {
			CWEID       []string `json:"cwe-id"`
			CVSSMetrics string   `json:"cvss-metrics"`
			CVSSScore   float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	IP          string `json:"ip"`
	Timestamp   string `json:"timestamp"`
	CurlCommand string `json:"curl-command"`
}

// Parse streams findings line by line from a Nuclei JSONL report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		scanner := bufio.NewScanner(r)
		// Max line size 10MB to accommodate large requests/responses
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		lineNum := 0
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var nf nucleiFinding
			if err := json.Unmarshal([]byte(line), &nf); err != nil {
				if pc.RecordError != nil {
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("line:%d", lineNum),
						Message: err.Error(),
					})
				}
				continue
			}

			if nf.TemplateID == "" {
				continue
			}

			rf := p.toRawFinding(nf, []byte(line))
			if !yield(rf, nil) {
				return
			}
		}

		if err := scanner.Err(); err != nil {
			yield(domain.RawFinding{}, err)
		}
	}
}

func (p *Parser) toRawFinding(nf nucleiFinding, raw []byte) domain.RawFinding {
	sev := domain.ParseSeverity(nf.Info.Severity)
	if sev == domain.SeverityUnknown || sev == "" {
		sev = domain.SeverityMedium
	}

	targetURL := nf.MatchedAt
	if targetURL == "" {
		targetURL = nf.Host
	}

	title := nf.Info.Name
	if title == "" {
		title = nf.TemplateID
	}

	desc := nf.Info.Description
	if desc == "" {
		desc = title
	}
	if nf.Info.Remediation != "" {
		desc += "\n\nRemediation: " + nf.Info.Remediation
	}

	var cwes []int
	for _, cweStr := range nf.Info.Classification.CWEID {
		var id int
		if _, err := fmt.Sscanf(strings.ToUpper(cweStr), "CWE-%d", &id); err == nil && id > 0 {
			cwes = append(cwes, id)
		}
	}

	return domain.RawFinding{
		RuleID:        nf.TemplateID,
		RuleName:      nf.Info.Name,
		ScannerFamily: "nuclei",
		Category:      domain.CategoryDAST,
		ToolRecordID:  fmt.Sprintf("%s:%s", nf.TemplateID, targetURL),
		ToolSeverity:  nf.Info.Severity,
		Severity:      sev,
		Title:         title,
		Description:   desc,
		Location: domain.Location{
			Web: &domain.WebLocation{
				NormalizedURL: targetURL,
			},
		},
		CWEs:       cwes,
		CVSSVector: nf.Info.Classification.CVSSMetrics,
		RawPayload: raw,
	}
}
