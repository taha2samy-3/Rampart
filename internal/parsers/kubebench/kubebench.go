// Package kubebench parses Aqua Security kube-bench CIS benchmark JSON reports (docs/16 D15, docs/21 §5.5).
package kubebench

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

// Parser reads kube-bench JSON reports.
type Parser struct{}

// NewParser returns a kube-bench parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "kubebench-json" }

// Detect scores how likely head is a kube-bench JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"Controls"`) || strings.Contains(s, `"node_type"`) {
		score += 45
	}
	if strings.Contains(s, `"test_number"`) && strings.Contains(s, `"test_desc"`) {
		score += 40
	}
	if strings.Contains(s, `"scored"`) && strings.Contains(s, `"remediation"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "kube-bench") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type kbResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Audit       string `json:"audit"`
	Remediation string `json:"remediation"`
	Status      string `json:"status"` // PASS | FAIL | WARN | INFO
	Scored      bool   `json:"scored"`
	Type        string `json:"type"`
}

type kbTest struct {
	Section string     `json:"section"`
	Type    string     `json:"type"`
	Desc    string     `json:"desc"`
	Results []kbResult `json:"results"`
}

type kbControl struct {
	ID       string   `json:"id"`
	Version  string   `json:"version"`
	Text     string   `json:"text"`
	NodeType string   `json:"node_type"`
	Tests    []kbTest `json:"tests"`
}

// Parse streams failed and warning checks from a kube-bench JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		br := bufio.NewReader(r)
		peek, _ := br.Peek(256)
		trimmed := bytes.TrimSpace(peek)

		if len(trimmed) > 0 && trimmed[0] == '[' {
			dec := json.NewDecoder(br)
			_ = parseutil.ArrayWith(dec, pc, "root", func() error {
				var ctrl kbControl
				raw, err := parseutil.Element(dec, &ctrl)
				if err != nil {
					return err
				}
				if !p.yieldControl(ctx, ctrl, raw, yield) {
					return io.EOF
				}
				return nil
			})
			return
		}

		dec := json.NewDecoder(br)
		_ = parseutil.Object(dec, func(key string) error {
			if key != "Controls" {
				var skip any
				return dec.Decode(&skip)
			}
			return parseutil.ArrayWith(dec, pc, "Controls", func() error {
				var ctrl kbControl
				raw, err := parseutil.Element(dec, &ctrl)
				if err != nil {
					return err
				}
				if !p.yieldControl(ctx, ctrl, raw, yield) {
					return io.EOF
				}
				return nil
			})
		})
	}
}

func (p *Parser) yieldControl(ctx context.Context, ctrl kbControl, raw json.RawMessage, yield func(domain.RawFinding, error) bool) bool {
	for _, t := range ctrl.Tests {
		for _, res := range t.Results {
			if ctx.Err() != nil {
				return false
			}

			status := strings.ToUpper(strings.TrimSpace(res.Status))
			// Only emit findings for FAIL and WARN
			if status != "FAIL" && status != "WARN" {
				continue
			}

			sev := domain.SeverityMedium
			switch status {
			case "FAIL":
				sev = domain.SeverityHigh
			case "WARN":
				sev = domain.SeverityLow
			}

			desc := res.TestDesc
			if res.Remediation != "" {
				desc += "\n\nRemediation:\n" + res.Remediation
			}
			if res.Audit != "" {
				desc += "\n\nAudit:\n" + res.Audit
			}

			rf := domain.RawFinding{
				RuleID:        res.TestNumber,
				RuleName:      res.TestDesc,
				ScannerFamily: "kube-bench",
				Category:      domain.CategoryCompliance,
				ToolRecordID:  fmt.Sprintf("%s:%s", ctrl.NodeType, res.TestNumber),
				ToolSeverity:  res.Status,
				Severity:      sev,
				Title:         fmt.Sprintf("CIS %s: %s", res.TestNumber, res.TestDesc),
				Description:   desc,
				Location: domain.Location{
					Resource: &domain.ResourceLocation{
						Address: fmt.Sprintf("k8s-node/%s", ctrl.NodeType),
						Type:    "kubernetes_node",
					},
				},
				RawPayload: raw,
			}

			if !yield(rf, nil) {
				return false
			}
		}
	}
	return true
}
