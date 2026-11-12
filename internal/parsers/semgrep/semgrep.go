// Package semgrep parses the JSON report of `semgrep --json`: one finding per result. A streaming walk over
// "results" (docs/16 D15).
package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Semgrep JSON reports.
type Parser struct{}

// NewParser returns a Semgrep parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "semgrep-json" }

// Detect scores how likely head is a Semgrep JSON report (not its SARIF output, which is the SARIF parser's).
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	if strings.Contains(s, `"runs"`) {
		return 0
	}
	score := 0
	if strings.Contains(s, `"results"`) {
		score += 40
	}
	if strings.Contains(s, `"check_id"`) {
		score += 40
	}
	if strings.Contains(s, `"extra"`) || strings.Contains(s, `"paths"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "semgrep") {
		score += 10
	}
	return min(score, 100)
}

var errStop = errors.New("stop")

type result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
		Metadata struct {
			CWE      json.RawMessage `json:"cwe"` // a string or a list of strings
			Category string          `json:"category"`
			Impact   string          `json:"impact"`
		} `json:"metadata"`
	} `json:"extra"`
}

// Semgrep's open-source build replaces the matched code with this text.
const hiddenLines = "requires login"

// Parse streams the findings of a Semgrep report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		version := ""
		err := parseutil.Object(dec, func(key string) error {
			switch key {
			case "version":
				return dec.Decode(&version)
			case "results":
				return parseutil.Array(dec, func() error {
					var res result
					raw, err := parseutil.Element(dec, &res)
					if err != nil {
						return err
					}
					if res.CheckID == "" || ctx.Err() != nil {
						return ctx.Err()
					}
					if !yield(mapResult(res, raw, version), nil) {
						return errStop
					}
					return nil
				})
			}
			return parseutil.Skip(dec)
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("semgrep: %w", err))
		}
	}
}

func mapResult(res result, raw json.RawMessage, version string) domain.RawFinding {
	// ERROR is high, WARNING medium, INFO low-information (parseutil via domain.ParseSeverity).
	sev := parseutil.Severity(res.Extra.Severity, 0)
	if sev == domain.SeverityUnknown {
		sev = domain.SeverityMedium
	}
	var cweStrings []string
	var one string
	if json.Unmarshal(res.Extra.Metadata.CWE, &one) == nil && one != "" {
		cweStrings = []string{one}
	} else {
		_ = json.Unmarshal(res.Extra.Metadata.CWE, &cweStrings)
	}
	category := domain.CategorySAST
	if strings.EqualFold(res.Extra.Metadata.Category, "secret") || strings.Contains(res.CheckID, ".secrets.") {
		category = domain.CategorySecret
	}
	code := &domain.CodeLocation{
		FilePath: normalize.CleanPath(res.Path), StartLine: res.Start.Line, EndLine: res.End.Line, StartColumn: res.Start.Col, EndColumn: res.End.Col,
	}
	if lines := strings.TrimSpace(res.Extra.Lines); lines != "" && lines != hiddenLines {
		code.Snippet = lines
		code.SnippetHash = normalize.ComputeSnippetHash(lines)
	}
	msg := strings.TrimSpace(res.Extra.Message)
	title := msg
	if i := strings.IndexAny(title, ".\n"); i > 0 && i < 200 {
		title = title[:i]
	} else if len(title) > 200 {
		title = title[:200]
	}
	if title == "" {
		title = res.CheckID
	}
	rf := domain.RawFinding{
		ScannerFamily: "semgrep", ScannerName: "semgrep", ScannerVersion: version, Category: category,
		RuleID: res.CheckID, Title: normalize.NFC(title), Description: normalize.NFC(msg),
		ToolSeverity: res.Extra.Severity, Severity: sev, CWEs: parseutil.CWEs(cweStrings...),
		Location: domain.Location{Code: code}, RawPayload: raw,
	}
	if category == domain.CategorySecret {
		// The matched code is the secret: it tells findings apart (hashed by the pipeline) and is not stored.
		if lines := strings.TrimSpace(res.Extra.Lines); lines != hiddenLines {
			rf.SecretValue = lines
		}
		rf.Location.Code.Snippet, rf.Location.Code.SnippetHash = "", ""
		rf.RawPayload = redactLines(raw)
	}
	return rf
}

// redactLines removes the matched code from a raw record, for rules that find secrets.
func redactLines(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	if extra, ok := m["extra"].(map[string]any); ok {
		if _, has := extra["lines"]; has {
			extra["lines"] = "[redacted]"
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}
