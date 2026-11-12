// Package gitleaks parses the JSON report of `gitleaks detect --report-format json`: an array with one object per
// secret found. A streaming walk over the array (docs/16 D15). The secret itself is used to tell findings apart and
// is never stored: it is removed from the raw record.
package gitleaks

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

// Parser reads Gitleaks JSON reports.
type Parser struct{}

// NewParser returns a Gitleaks parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "gitleaks-json" }

// Detect scores how likely head is a Gitleaks JSON report: an array of objects with RuleID, StartLine and File.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := strings.TrimSpace(string(head))
	if !strings.HasPrefix(s, "[") {
		return 0
	}
	score := 0
	if strings.Contains(s, `"RuleID"`) {
		score += 40
	}
	if strings.Contains(s, `"StartLine"`) && strings.Contains(s, `"File"`) {
		score += 30
	}
	if strings.Contains(s, `"Secret"`) || strings.Contains(s, `"Fingerprint"`) || strings.Contains(s, `"Entropy"`) {
		score += 20
	}
	if strings.Contains(strings.ToLower(filename), "gitleaks") {
		score += 10
	}
	if score < 40 { // an array of something else
		return 0
	}
	return min(score, 100)
}

var errStop = errors.New("stop")

type leak struct {
	Description string   `json:"Description"`
	RuleID      string   `json:"RuleID"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Secret      string   `json:"Secret"`
	Match       string   `json:"Match"`
	Tags        []string `json:"Tags"`
}

// redacted is what replaces the secret and the matched text in the stored record.
const redacted = "[redacted]"

// Parse streams the findings of a Gitleaks report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		err := parseutil.ArrayWith(dec, pc, "findings", func() error {
			var l leak
			raw, err := parseutil.Element(dec, &l)
			if err != nil {
				return err
			}
			if l.RuleID == "" || ctx.Err() != nil {
				return ctx.Err()
			}
			if !yield(mapLeak(l, raw), nil) {
				return errStop
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("gitleaks: %w", err))
		}
	}
}

func mapLeak(l leak, raw json.RawMessage) domain.RawFinding {
	title := l.Description
	if title == "" {
		title = l.RuleID
	}
	return domain.RawFinding{
		ScannerFamily: "gitleaks", ScannerName: "gitleaks", Category: domain.CategorySecret,
		RuleID: l.RuleID, Title: normalize.NFC(title), Description: normalize.NFC(l.Description),
		// A secret in a repository is a credential that has already leaked: high, whatever the rule.
		ToolSeverity: "high", Severity: domain.SeverityHigh, SecretValue: l.Secret,
		Location: domain.Location{Code: &domain.CodeLocation{
			FilePath: normalize.CleanPath(l.File), StartLine: l.StartLine, EndLine: l.EndLine, StartColumn: l.StartColumn, EndColumn: l.EndColumn,
		}},
		RawPayload: redact(raw),
	}
}

// redact removes the secret and the matched text (which contains it) from a record before it is stored.
func redact(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil // an unreadable record is not stored: it might hold the secret
	}
	for _, k := range []string{"Secret", "Match"} {
		if _, ok := m[k]; ok {
			m[k] = redacted
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}
