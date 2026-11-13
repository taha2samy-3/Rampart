// Package zap parses OWASP ZAP JSON reports (docs/16 D15, docs/21 §5.5).
package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/parsers/parseutil"
)

// Parser reads OWASP ZAP JSON reports.
type Parser struct{}

// NewParser returns a ZAP parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "owasp-zap-json" }

// Detect scores how likely head is a ZAP JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"@programName"`) && strings.Contains(s, `"ZAP"`) {
		score += 50
	}
	if strings.Contains(s, `"site"`) && strings.Contains(s, `"alerts"`) {
		score += 35
	}
	if strings.Contains(s, `"pluginId"`) && strings.Contains(s, `"riskcode"`) {
		score += 20
	}
	if strings.Contains(strings.ToLower(filename), "zap") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Attack   string `json:"attack"`
	Evidence string `json:"evidence"`
}

type zapAlert struct {
	PluginID  string        `json:"pluginId"`
	Alert     string        `json:"alert"`
	Name      string        `json:"name"`
	RiskCode  string        `json:"riskcode"`
	RiskDesc  string        `json:"riskdesc"`
	Desc      string        `json:"desc"`
	Solution  string        `json:"solution"`
	Reference string        `json:"reference"`
	CWEID     string        `json:"cweid"`
	WASCID    string        `json:"wascid"`
	Instances []zapInstance `json:"instances"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Host   string     `json:"@host"`
	Port   string     `json:"@port"`
	Alerts []zapAlert `json:"alerts"`
}

// Parse streams findings from a ZAP JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		err := parseutil.Object(dec, func(key string) error {
			if key != "site" {
				var skip any
				return dec.Decode(&skip)
			}

			return parseutil.ArrayWith(dec, pc, "site", func() error {
				var site zapSite
				raw, err := parseutil.Element(dec, &site)
				if err != nil {
					return err
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}

				for _, alert := range site.Alerts {
					rfs := p.toRawFindings(alert, site.Name, raw)
					for _, rf := range rfs {
						if !yield(rf, nil) {
							return io.EOF
						}
					}
				}
				return nil
			})
		})

		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "stop") {
			yield(domain.RawFinding{}, err)
		}
	}
}

func (p *Parser) toRawFindings(alert zapAlert, siteName string, raw json.RawMessage) []domain.RawFinding {
	title := alert.Alert
	if title == "" {
		title = alert.Name
	}
	if title == "" {
		title = "ZAP Alert " + alert.PluginID
	}

	// ZAP risk codes: 0 = Informational, 1 = Low, 2 = Medium, 3 = High
	var sev domain.Severity
	switch strings.TrimSpace(alert.RiskCode) {
	case "3":
		sev = domain.SeverityHigh
	case "2":
		sev = domain.SeverityMedium
	case "1":
		sev = domain.SeverityLow
	case "0":
		sev = domain.SeverityInfo
	default:
		sev = domain.ParseSeverity(alert.RiskDesc)
		if sev == domain.SeverityUnknown || sev == "" {
			sev = domain.SeverityMedium
		}
	}

	desc := alert.Desc
	if alert.Solution != "" {
		desc += "\n\nSolution: " + alert.Solution
	}

	var cwes []int
	if cwe, err := strconv.Atoi(strings.TrimSpace(alert.CWEID)); err == nil && cwe > 0 {
		cwes = []int{cwe}
	}

	if len(alert.Instances) == 0 {
		return []domain.RawFinding{
			{
				RuleID:        alert.PluginID,
				RuleName:      title,
				ScannerFamily: "zap",
				Category:      domain.CategoryDAST,
				ToolRecordID:  fmt.Sprintf("%s:%s", alert.PluginID, siteName),
				ToolSeverity:  alert.RiskDesc,
				Severity:      sev,
				Title:         title,
				Description:   desc,
				Location: domain.Location{
					Web: &domain.WebLocation{
						NormalizedURL: siteName,
					},
				},
				CWEs:       cwes,
				RawPayload: raw,
			},
		}
	}

	var findings []domain.RawFinding
	for _, inst := range alert.Instances {
		targetURL := inst.URI
		if targetURL == "" {
			targetURL = siteName
		}

		instDesc := desc
		if inst.Evidence != "" {
			instDesc += "\n\nEvidence: " + inst.Evidence
		}

		findings = append(findings, domain.RawFinding{
			RuleID:        alert.PluginID,
			RuleName:      title,
			ScannerFamily: "zap",
			Category:      domain.CategoryDAST,
			ToolRecordID:  fmt.Sprintf("%s:%s:%s", alert.PluginID, targetURL, inst.Param),
			ToolSeverity:  alert.RiskDesc,
			Severity:      sev,
			Title:         title,
			Description:   instDesc,
			Location: domain.Location{
				Web: &domain.WebLocation{
					NormalizedURL: targetURL,
					Parameter:     inst.Param,
					Method:        inst.Method,
				},
			},
			CWEs:       cwes,
			RawPayload: raw,
		})
	}

	return findings
}
