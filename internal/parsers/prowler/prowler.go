// Package prowler parses Prowler cloud security JSON reports (docs/16 D15, docs/21 §5.5).
package prowler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Prowler JSON / OCSF reports.
type Parser struct{}

// NewParser returns a Prowler parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "prowler-json" }

// Detect scores how likely head is a Prowler JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"CheckID"`) || strings.Contains(s, `"check_id"`) {
		score += 40
	}
	if strings.Contains(s, `"ServiceName"`) || strings.Contains(s, `"service_name"`) {
		score += 30
	}
	if strings.Contains(s, `"ResourceId"`) || strings.Contains(s, `"resource_id"`) || strings.Contains(s, `"ResourceArn"`) {
		score += 20
	}
	if strings.Contains(strings.ToLower(filename), "prowler") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type prowlerFinding struct {
	CheckID     string `json:"CheckID"`
	CheckTitle  string `json:"CheckTitle"`
	Status      string `json:"Status"` // PASS | FAIL | WARNING | INFO | MUTED
	Severity    string `json:"Severity"`
	ServiceName string `json:"ServiceName"`
	Region      string `json:"Region"`
	ResourceID  string `json:"ResourceId"`
	ResourceARN string `json:"ResourceArn"`
	Description string `json:"Description"`
	Risk        string `json:"Risk"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
		Code struct {
			CLI string `json:"CLI"`
		} `json:"Code"`
	} `json:"Remediation"`
}

// Parse streams failed and warning findings from a Prowler report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		br := bufio.NewReader(r)
		peek, _ := br.Peek(256)
		trimmed := bytes.TrimSpace(peek)

		dec := json.NewDecoder(br)

		if len(trimmed) > 0 && trimmed[0] == '[' {
			_ = parseutil.ArrayWith(dec, pc, "root", func() error {
				var pf prowlerFinding
				raw, err := parseutil.Element(dec, &pf)
				if err != nil {
					return err
				}
				if !p.yieldFinding(ctx, pf, raw, yield) {
					return io.EOF
				}
				return nil
			})
			return
		}

		// Or line-delimited JSON
		scanner := bufio.NewScanner(br)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		lineIdx := 0
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			lineIdx++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var pf prowlerFinding
			if err := json.Unmarshal([]byte(line), &pf); err != nil {
				if pc.RecordError != nil {
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("line:%d", lineIdx),
						Message: err.Error(),
					})
				}
				continue
			}

			if !p.yieldFinding(ctx, pf, []byte(line), yield) {
				return
			}
		}
	}
}

func (p *Parser) yieldFinding(ctx context.Context, pf prowlerFinding, raw []byte, yield func(domain.RawFinding, error) bool) bool {
	if pf.CheckID == "" {
		return true
	}

	status := strings.ToUpper(strings.TrimSpace(pf.Status))
	if status != "FAIL" && status != "WARNING" && status != "WARN" {
		return true // skip PASS / INFO
	}

	sev := domain.ParseSeverity(pf.Severity)
	if sev == domain.SeverityUnknown || sev == "" {
		sev = domain.SeverityMedium
	}

	resource := pf.ResourceID
	if resource == "" {
		resource = pf.ResourceARN
	}

	desc := pf.Description
	if pf.Risk != "" {
		desc += "\n\nRisk: " + pf.Risk
	}
	if pf.Remediation.Recommendation.Text != "" {
		desc += "\n\nRemediation:\n" + pf.Remediation.Recommendation.Text
	}

	rf := domain.RawFinding{
		RuleID:        pf.CheckID,
		RuleName:      pf.CheckTitle,
		ScannerFamily: "prowler",
		Category:      domain.CategoryCSPM,
		ToolRecordID:  fmt.Sprintf("%s:%s", pf.CheckID, resource),
		ToolSeverity:  pf.Severity,
		Severity:      sev,
		Title:         fmt.Sprintf("%s: %s", pf.CheckTitle, resource),
		Description:   desc,
		Location: domain.Location{
			Resource: &domain.ResourceLocation{
				Address: resource,
				Key:     pf.ResourceARN,
				Type:    pf.ServiceName,
			},
		},
		RawPayload: raw,
	}

	return yield(rf, nil)
}
