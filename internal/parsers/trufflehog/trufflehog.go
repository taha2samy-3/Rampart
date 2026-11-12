// Package trufflehog parses the JSON lines of `trufflehog ... --json`: one object per secret found. Unlike the other
// secret scanners, TruffleHog tries the credential against its provider, and says so (`Verified`): a live secret
// is what the risk score weighs most (docs/06, SECRET_VERIFIED). The secret itself is used to tell findings apart
// and is never stored: it is removed from the raw record.
package trufflehog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// Parser reads TruffleHog JSON-lines reports.
type Parser struct{}

// NewParser returns a TruffleHog parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "trufflehog-json" }

// Detect scores how likely head is TruffleHog JSON lines.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"DetectorName"`) {
		score += 40
	}
	if strings.Contains(s, `"SourceMetadata"`) {
		score += 30
	}
	if strings.Contains(s, `"Verified"`) {
		score += 20
	}
	if strings.Contains(strings.ToLower(filename), "trufflehog") {
		score += 10
	}
	if score < 60 {
		return 0
	}
	return min(score, 100)
}

// MaxLine bounds one record: a line longer than this is refused rather than buffered.
const MaxLine = 4 << 20

type finding struct {
	SourceMetadata struct {
		Data map[string]json.RawMessage `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName string `json:"DetectorName"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	RawV2        string `json:"RawV2"`
	Redacted     string `json:"Redacted"`
}

// where is the source-specific part of a record: Git, Filesystem, Docker and the others each name the file and
// the line in their own object.
type where struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Image string `json:"image"`
}

// Parse streams the findings of a TruffleHog report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(io.LimitReader(r, 1<<40))
		n := 0
		for dec.More() {
			n++
			if ctx.Err() != nil {
				return
			}
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				yield(domain.RawFinding{}, fmt.Errorf("trufflehog: %w", err))
				return
			}
			if len(raw) > MaxLine {
				yield(domain.RawFinding{}, errors.New("trufflehog: a record is larger than the limit"))
				return
			}
			var f finding
			if err := json.Unmarshal(raw, &f); err != nil {
				if pc.RecordError != nil { // one bad record does not stop the report
					pc.RecordError(domain.RecordError{Where: fmt.Sprintf("record %d", n), Message: "the record does not have the shape this tool writes (" + err.Error() + ")"})
					continue
				}
				yield(domain.RawFinding{}, fmt.Errorf("trufflehog: %w", err))
				return
			}
			if f.DetectorName == "" { // a log line or a record of another shape
				continue
			}
			if !yield(mapFinding(f, raw), nil) {
				return
			}
		}
	}
}

func mapFinding(f finding, raw json.RawMessage) domain.RawFinding {
	var w where
	for _, data := range f.SourceMetadata.Data { // Git, Filesystem, Docker...: the one object that names a file
		var cand where
		if json.Unmarshal(data, &cand) == nil && cand.File != "" {
			w = cand
			break
		}
	}
	secret := f.RawV2
	if secret == "" {
		secret = f.Raw
	}
	sev, tool, state := domain.SeverityHigh, "unverified", "The credential was not verified: it may be a false positive or already revoked."
	if f.Verified {
		sev, tool, state = domain.SeverityCritical, "verified", "The credential was verified against its provider: it is live."
	}
	rule := strings.ToLower(strings.TrimSpace(f.DetectorName))
	return domain.RawFinding{
		ScannerFamily: "trufflehog", ScannerName: "trufflehog", Category: domain.CategorySecret,
		RuleID: rule, Title: normalize.NFC(f.DetectorName + " credential detected"), Description: normalize.NFC(state),
		ToolSeverity: tool, Severity: sev, SecretValue: secret, SecretVerified: f.Verified,
		Location: domain.Location{Code: &domain.CodeLocation{FilePath: normalize.CleanPath(w.File), StartLine: w.Line}, Image: w.Image},
		// What is kept: the record without the credential.
		RawPayload: redact(raw),
	}
}

// redact removes the credential (Raw and RawV2) from a record before it is stored, and shortens the masked form.
func redact(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(raw), &m) != nil {
		return nil
	}
	// Redacted is TruffleHog's masked form, but a detector may mask little: for AWS it is the whole access key id,
	// for a GitHub token its first 20 characters. Nothing of a credential is stored beyond its first four
	// characters; the detector name already says what kind it is.
	if red, ok := m["Redacted"].(string); ok && len(red) > 4 {
		m["Redacted"] = red[:4] + "..."
	}
	for _, k := range []string{"Raw", "RawV2"} {
		if _, ok := m[k]; ok {
			m[k] = "[redacted]"
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}
