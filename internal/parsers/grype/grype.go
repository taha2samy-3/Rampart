// Package grype parses the JSON report of `grype -o json`: one finding per match of a vulnerability against a
// package. A streaming walk over "matches" (docs/16 D15).
package grype

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

// Parser reads Grype JSON reports.
type Parser struct{}

// NewParser returns a Grype parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "grype-json" }

// Detect scores how likely head is a Grype JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	if strings.Contains(s, `"runs"`) {
		return 0
	}
	score := 0
	if strings.Contains(s, `"matches"`) {
		score += 45
	}
	if strings.Contains(s, `"vulnerability"`) || strings.Contains(s, `"artifact"`) {
		score += 30
	}
	if strings.Contains(s, `"descriptor"`) || strings.Contains(s, `"matchDetails"`) || strings.Contains(s, `"relatedVulnerabilities"`) {
		score += 20
	}
	if strings.Contains(strings.ToLower(filename), "grype") {
		score += 10
	}
	return min(score, 100)
}

var errStop = errors.New("stop")

type match struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		CVSS        []struct {
			Version string `json:"version"`
			Vector  string `json:"vector"`
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
		Fix struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Related []struct {
		ID string `json:"id"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	} `json:"artifact"`
}

// Parse streams the findings of a Grype report. "ignoredMatches" (what a Grype ignore rule suppressed) is not read.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		err := parseutil.Object(dec, func(key string) error {
			if key != "matches" {
				return parseutil.Skip(dec)
			}
			return parseutil.ArrayWith(dec, pc, "matches", func() error {
				var m match
				raw, err := parseutil.Element(dec, &m)
				if err != nil {
					return err
				}
				if m.Vulnerability.ID == "" || ctx.Err() != nil {
					return ctx.Err()
				}
				if !yield(mapMatch(m, raw), nil) {
					return errStop
				}
				return nil
			})
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("grype: %w", err))
		}
	}
}

func mapMatch(m match, raw json.RawMessage) domain.RawFinding {
	v := m.Vulnerability
	var bestScore float64
	var bestVector string
	for _, c := range v.CVSS {
		if c.Metrics.BaseScore > bestScore {
			bestScore, bestVector = c.Metrics.BaseScore, c.Vector
		}
	}
	// The id Grype matched on first, then the identifiers it relates to it (the CVE of a GHSA, for example): the
	// pipeline picks the CVE as the canonical one (docs/16 D11).
	ids := []string{v.ID}
	for _, rel := range m.Related {
		if rel.ID != "" && rel.ID != v.ID {
			ids = append(ids, rel.ID)
		}
	}
	fixed := ""
	if len(v.Fix.Versions) > 0 {
		fixed = strings.Join(v.Fix.Versions, ", ")
	}
	manifest := ""
	if len(m.Artifact.Locations) > 0 {
		manifest = m.Artifact.Locations[0].Path
	}
	return domain.RawFinding{
		ScannerFamily: "grype", ScannerName: "grype", Category: domain.CategorySCA,
		RuleID: v.ID, Title: normalize.NFC(fmt.Sprintf("%s: %s", m.Artifact.Name, v.ID)), Description: normalize.NFC(v.Description),
		ToolSeverity: v.Severity, Severity: parseutil.Severity(v.Severity, bestScore),
		VulnIDs: ids, CVSSVector: bestVector,
		Location:   domain.Location{Package: parseutil.Package(m.Artifact.PURL, m.Artifact.Name, m.Artifact.Version, fixed, manifest)},
		RawPayload: raw,
	}
}
