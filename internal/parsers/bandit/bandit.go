// Package bandit parses Bandit Python SAST JSON reports (docs/16 D15, docs/21 §5.5).
package bandit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Bandit JSON reports.
type Parser struct{}

// NewParser returns a Bandit parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "bandit-json" }

// Detect scores how likely head is a Bandit JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"results"`) && strings.Contains(s, `"metrics"`) {
		score += 40
	}
	if strings.Contains(s, `"test_id"`) && strings.Contains(s, `"test_name"`) {
		score += 40
	}
	if strings.Contains(s, `"issue_severity"`) && strings.Contains(s, `"issue_confidence"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "bandit") {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}

type banditFinding struct {
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	IssueText       string `json:"issue_text"`
	IssueSeverity   string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueCWE        struct {
		ID  int    `json:"id"`
		URL string `json:"url"`
	} `json:"issue_cwe"`
	Filename   string `json:"filename"`
	LineNumber int    `json:"line_number"`
	Code       string `json:"code"`
	MoreInfo   string `json:"more_info"`
}

// Parse streams findings from a Bandit JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		err := parseutil.Object(dec, func(key string) error {
			if key != "results" {
				var skip any
				return dec.Decode(&skip)
			}

			return parseutil.ArrayWith(dec, pc, "results", func() error {
				var bf banditFinding
				raw, err := parseutil.Element(dec, &bf)
				if err != nil {
					return err
				}
				if bf.TestID == "" || ctx.Err() != nil {
					return ctx.Err()
				}

				rf := p.toRawFinding(bf, raw)
				if !yield(rf, nil) {
					return io.EOF
				}
				return nil
			})
		})

		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "stop") {
			yield(domain.RawFinding{}, err)
		}
	}
}

func (p *Parser) toRawFinding(bf banditFinding, raw json.RawMessage) domain.RawFinding {
	sev := domain.ParseSeverity(bf.IssueSeverity)
	if sev == domain.SeverityUnknown || sev == "" {
		sev = domain.SeverityMedium
	}

	var cwes []int
	if bf.IssueCWE.ID > 0 {
		cwes = []int{bf.IssueCWE.ID}
	}

	desc := bf.IssueText
	if bf.MoreInfo != "" {
		desc += "\n\nMore info: " + bf.MoreInfo
	}

	return domain.RawFinding{
		RuleID:        bf.TestID,
		RuleName:      bf.TestName,
		ScannerFamily: "bandit",
		Category:      domain.CategorySAST,
		ToolRecordID:  fmt.Sprintf("%s:%d:%s", bf.Filename, bf.LineNumber, bf.TestID),
		ToolSeverity:  bf.IssueSeverity,
		Severity:      sev,
		Title:         bf.IssueText,
		Description:   desc,
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  bf.Filename,
				StartLine: bf.LineNumber,
				Snippet:   bf.Code,
			},
		},
		CWEs:       cwes,
		RawPayload: raw,
	}
}
