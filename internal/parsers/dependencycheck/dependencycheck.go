// Package dependencycheck parses OWASP Dependency-Check JSON reports (docs/16 D15, docs/21 §5.5).
package dependencycheck

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

// Parser reads OWASP Dependency-Check JSON reports.
type Parser struct{}

// NewParser returns a Dependency-Check parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "owasp-dependency-check-json" }

// Detect scores how likely head is a Dependency-Check JSON report.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	score := 0
	if strings.Contains(s, `"reportSchema"`) && strings.Contains(s, `"dependencies"`) {
		score += 45
	}
	if strings.Contains(s, `"vulnerabilities"`) && strings.Contains(s, `"cvssv3"`) {
		score += 35
	}
	if strings.Contains(s, `"projectInfo"`) || strings.Contains(s, `"scanInfo"`) {
		score += 15
	}
	if strings.Contains(strings.ToLower(filename), "dependency-check") {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

type dcVulnerability struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	CVSSv3      struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssv3"`
	CVSSv2 struct {
		Score float64 `json:"score"`
	} `json:"cvssv2"`
	CWEs []string `json:"cwes"`
}

type dcDependency struct {
	FileName    string `json:"fileName"`
	FilePath    string `json:"filePath"`
	Description string `json:"description"`
	Packages    []struct {
		ID  string `json:"id"` // purl e.g. pkg:maven/org.apache/log4j@2.14.1
		URL string `json:"url"`
	} `json:"packages"`
	Vulnerabilities []dcVulnerability `json:"vulnerabilities"`
}

// Parse streams findings from a Dependency-Check JSON report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		err := parseutil.Object(dec, func(key string) error {
			if key != "dependencies" {
				var skip any
				return dec.Decode(&skip)
			}

			return parseutil.ArrayWith(dec, pc, "dependencies", func() error {
				var dep dcDependency
				raw, err := parseutil.Element(dec, &dep)
				if err != nil {
					return err
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}

				if len(dep.Vulnerabilities) == 0 {
					return nil
				}

				purl := ""
				if len(dep.Packages) > 0 {
					purl = dep.Packages[0].ID
				}

				for _, vuln := range dep.Vulnerabilities {
					rf := p.toRawFinding(vuln, dep, purl, raw)
					if !yield(rf, nil) {
						return io.EOF
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

func (p *Parser) toRawFinding(vuln dcVulnerability, dep dcDependency, purl string, raw json.RawMessage) domain.RawFinding {
	sev := domain.ParseSeverity(vuln.Severity)
	if sev == domain.SeverityUnknown || sev == "" {
		if vuln.CVSSv3.BaseScore >= 9.0 {
			sev = domain.SeverityCritical
		} else if vuln.CVSSv3.BaseScore >= 7.0 {
			sev = domain.SeverityHigh
		} else if vuln.CVSSv3.BaseScore >= 4.0 {
			sev = domain.SeverityMedium
		} else if vuln.CVSSv3.BaseScore > 0.0 {
			sev = domain.SeverityLow
		} else {
			sev = domain.SeverityMedium
		}
	}

	title := fmt.Sprintf("%s in %s", vuln.Name, dep.FileName)

	var cwes []int
	for _, cweStr := range vuln.CWEs {
		clean := strings.TrimSpace(strings.ToUpper(cweStr))
		clean = strings.TrimPrefix(clean, "CWE-")
		if id, err := strconv.Atoi(clean); err == nil && id > 0 {
			cwes = append(cwes, id)
		}
	}

	return domain.RawFinding{
		RuleID:        vuln.Name,
		RuleName:      vuln.Name,
		ScannerFamily: "dependency-check",
		Category:      domain.CategorySCA,
		ToolRecordID:  fmt.Sprintf("%s:%s", dep.FileName, vuln.Name),
		ToolSeverity:  vuln.Severity,
		Severity:      sev,
		Title:         title,
		Description:   vuln.Description,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:          purl,
				ComponentName: dep.FileName,
				ManifestPath:  dep.FilePath,
			},
		},
		CWEs:       cwes,
		VulnIDs:    []string{vuln.Name},
		CVSSVector: vuln.CVSSv3.VectorString,
		RawPayload: raw,
	}
}
