// Package snyk parses Snyk CLI JSON reports (docs/16 D15, docs/21 §5.5).
package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"rampart/internal/domain"
)

// Parser reads Snyk JSON reports.
type Parser struct{}

// NewParser returns a Snyk parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "snyk-json" }

// Detect scores how likely head is a Snyk JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"vulnerabilities"`) && strings.Contains(s, `"packageManager"`) {
		score += 45
	}
	if strings.Contains(s, `"SNYK-`) || strings.Contains(s, `"snyk"`) {
		score += 35
	}
	if strings.Contains(s, `"filtered"`) || strings.Contains(s, `"uniqueCount"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "snyk") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type snykFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	FixedIn     []string `json:"fixedIn"`
	CVSSv3      string   `json:"CVSSv3"`
	CVSSScore   float64  `json:"cvssScore"`
	Identifiers struct {
		CVE  []string `json:"CVE"`
		CWE  []string `json:"CWE"`
		GHSA []string `json:"GHSA"`
	} `json:"identifiers"`
	From []string `json:"from"`
}

// Parse streams findings from a Snyk JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		tok, err := dec.Token()
		if err != nil {
			yield(domain.RawFinding{}, err)
			return
		}

		if tok == json.Delim('[') {
			// Multi-project array
			for dec.More() {
				if ctx.Err() != nil {
					return
				}
				if err := p.parseProjectObject(ctx, dec, pc, yield); err != nil {
					return
				}
			}
			_, _ = dec.Token() // closing ']'
			return
		}

		if tok == json.Delim('{') {
			_ = p.walkProjectKeys(ctx, dec, pc, yield)
		}
	}
}

func (p *Parser) parseProjectObject(ctx context.Context, dec *json.Decoder, pc domain.ParseContext, yield func(domain.RawFinding, error) bool) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		var skip any
		return dec.Decode(&skip)
	}
	return p.walkProjectKeys(ctx, dec, pc, yield)
}

func (p *Parser) walkProjectKeys(ctx context.Context, dec *json.Decoder, pc domain.ParseContext, yield func(domain.RawFinding, error) bool) error {
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

		if key == "vulnerabilities" {
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
				var sf snykFinding
				if err := dec.Decode(&sf); err != nil {
					if pc.RecordError != nil {
						pc.RecordError(domain.RecordError{
							Where:   fmt.Sprintf("vulnerabilities[%d]", idx),
							Message: err.Error(),
						})
					}
					idx++
					continue
				}
				idx++

				if sf.ID == "" {
					continue
				}

				raw, _ := json.Marshal(sf)
				rf := p.toRawFinding(sf, raw)
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
	_, _ = dec.Token() // closing '}'
	return nil
}

func (p *Parser) toRawFinding(sf snykFinding, raw json.RawMessage) domain.RawFinding {
	sev := domain.ParseSeverity(sf.Severity)
	if sev == domain.SeverityUnknown || sev == "" {
		sev = domain.SeverityMedium
	}

	var vulnIDs []string
	vulnIDs = append(vulnIDs, sf.Identifiers.CVE...)
	vulnIDs = append(vulnIDs, sf.Identifiers.GHSA...)
	if len(vulnIDs) == 0 {
		vulnIDs = []string{sf.ID}
	}

	var cwes []int
	for _, c := range sf.Identifiers.CWE {
		clean := strings.TrimPrefix(strings.TrimSpace(strings.ToUpper(c)), "CWE-")
		if id, err := strconv.Atoi(clean); err == nil && id > 0 {
			cwes = append(cwes, id)
		}
	}

	fixedVer := ""
	if len(sf.FixedIn) > 0 {
		fixedVer = sf.FixedIn[0]
	}

	title := sf.Title
	if title == "" {
		title = fmt.Sprintf("%s in %s", sf.ID, sf.PackageName)
	}

	return domain.RawFinding{
		RuleID:        sf.ID,
		RuleName:      sf.Title,
		ScannerFamily: "snyk",
		Category:      domain.CategorySCA,
		ToolRecordID:  fmt.Sprintf("%s:%s@%s", sf.ID, sf.PackageName, sf.Version),
		ToolSeverity:  sf.Severity,
		Severity:      sev,
		Title:         title,
		Description:   sf.Description,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				ComponentName:    sf.PackageName,
				InstalledVersion: sf.Version,
				FixedVersion:     fixedVer,
			},
		},
		CWEs:       cwes,
		VulnIDs:    vulnIDs,
		CVSSVector: sf.CVSSv3,
		RawPayload: raw,
	}
}
