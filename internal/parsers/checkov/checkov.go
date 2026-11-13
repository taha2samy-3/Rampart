// Package checkov parses Checkov IaC JSON reports (docs/16 D15, docs/21 §5.5).
package checkov

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
)

// Parser reads Checkov JSON reports.
type Parser struct{}

// NewParser returns a Checkov parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "checkov-json" }

// Detect scores how likely head is a Checkov JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"check_type"`) || strings.Contains(s, `"results"`) {
		score += 35
	}
	if strings.Contains(s, `"failed_checks"`) || strings.Contains(s, `"passed_checks"`) {
		score += 45
	}
	if strings.Contains(s, `"check_id"`) && strings.Contains(s, `"check_name"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "checkov") {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}

type checkovFinding struct {
	CheckID     string `json:"check_id"`
	CheckName   string `json:"check_name"`
	CheckResult struct {
		Result string `json:"result"`
	} `json:"check_result"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Resource      string `json:"resource"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	Guideline     string `json:"guideline"`
	CheckClass    string `json:"check_class"`
}

// Parse streams failed checks from a Checkov JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		// Checkov can produce a single object or an array of check_type reports
		tok, err := dec.Token()
		if err != nil {
			yield(domain.RawFinding{}, err)
			return
		}

		if tok == json.Delim('[') {
			for dec.More() {
				if ctx.Err() != nil {
					return
				}
				if err := p.parseReportObject(ctx, dec, pc, yield); err != nil {
					return
				}
			}
			_, _ = dec.Token() // closing ']'
			return
		}

		if tok == json.Delim('{') {
			_ = p.walkReportKeys(ctx, dec, pc, yield)
		}
	}
}

func (p *Parser) parseReportObject(ctx context.Context, dec *json.Decoder, pc domain.ParseContext, yield func(domain.RawFinding, error) bool) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		var skip any
		return dec.Decode(&skip)
	}
	return p.walkReportKeys(ctx, dec, pc, yield)
}

func (p *Parser) walkReportKeys(ctx context.Context, dec *json.Decoder, pc domain.ParseContext, yield func(domain.RawFinding, error) bool) error {
	for dec.More() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		tKey, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tKey.(string)
		if !ok {
			continue
		}

		if key == "results" {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if tok != json.Delim('{') {
				var skip any
				_ = dec.Decode(&skip)
				continue
			}

			for dec.More() {
				rKeyTok, err := dec.Token()
				if err != nil {
					return err
				}
				rKey, ok := rKeyTok.(string)
				if !ok {
					continue
				}

				if rKey == "failed_checks" {
					tok, err := dec.Token()
					if err != nil {
						return err
					}
					if tok != json.Delim('[') {
						var skip any
						_ = dec.Decode(&skip)
						continue
					}

					idx := 0
					for dec.More() {
						if ctx.Err() != nil {
							return ctx.Err()
						}
						var cf checkovFinding
						if err := dec.Decode(&cf); err != nil {
							if pc.RecordError != nil {
								pc.RecordError(domain.RecordError{
									Where:   fmt.Sprintf("results.failed_checks[%d]", idx),
									Message: err.Error(),
								})
							}
							idx++
							continue
						}
						idx++

						if cf.CheckID == "" {
							continue
						}

						rf := p.toRawFinding(cf)
						if !yield(rf, nil) {
							return nil
						}
					}
					_, _ = dec.Token() // closing ']'
				} else {
					var skip any
					_ = dec.Decode(&skip)
				}
			}
			_, _ = dec.Token() // closing '}' of results
		} else {
			var skip any
			_ = dec.Decode(&skip)
		}
	}
	_, _ = dec.Token() // closing '}' of report
	return nil
}

func (p *Parser) toRawFinding(cf checkovFinding) domain.RawFinding {
	sev := domain.ParseSeverity(cf.Severity)
	if sev == domain.SeverityUnknown || sev == "" {
		sev = domain.SeverityMedium
	}

	startLine := 1
	endLine := 1
	if len(cf.FileLineRange) >= 1 {
		startLine = cf.FileLineRange[0]
	}
	if len(cf.FileLineRange) >= 2 {
		endLine = cf.FileLineRange[1]
	}

	desc := cf.Description
	if desc == "" {
		desc = cf.CheckName
	}
	if cf.Guideline != "" {
		desc += "\n\nGuideline: " + cf.Guideline
	}

	raw, _ := json.Marshal(cf)

	return domain.RawFinding{
		RuleID:        cf.CheckID,
		RuleName:      cf.CheckName,
		ScannerFamily: "checkov",
		Category:      domain.CategoryIaC,
		ToolRecordID:  fmt.Sprintf("%s:%s", cf.FilePath, cf.Resource),
		ToolSeverity:  cf.Severity,
		Severity:      sev,
		Title:         fmt.Sprintf("%s on %s", cf.CheckName, cf.Resource),
		Description:   desc,
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  cf.FilePath,
				StartLine: startLine,
				EndLine:   endLine,
			},
			Resource: &domain.ResourceLocation{
				Address: cf.Resource,
				Type:    cf.CheckClass,
			},
		},
		RawPayload: raw,
	}
}
