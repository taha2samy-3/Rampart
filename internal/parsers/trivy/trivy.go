// Package trivy parses the JSON report of `trivy ... --format json` (schema version 2): vulnerabilities of OS and
// language packages, secrets, misconfigurations and licenses. It is a streaming walk (docs/16 D15): one finding at
// a time, so the size of the report does not set the memory used.
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/url"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Trivy JSON reports.
type Parser struct{}

// NewParser returns a Trivy parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "trivy-json" }

// Detect scores how likely head is a Trivy JSON report. A SARIF file (which Trivy can also write) has "runs" and
// is the SARIF parser's.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	if strings.Contains(s, `"runs"`) || strings.Contains(s, "sarif") {
		return 0
	}
	score := 0
	if strings.Contains(s, `"SchemaVersion"`) {
		score += 40
	}
	if strings.Contains(s, `"ArtifactName"`) || strings.Contains(s, `"ArtifactType"`) {
		score += 30
	}
	if strings.Contains(s, `"Results"`) {
		score += 25
	}
	if strings.Contains(strings.ToLower(filename), "trivy") {
		score += 10
	}
	return min(score, 100)
}

var errStop = errors.New("stop")

type result struct{ target, class, typ string }

type metadata struct {
	OS struct {
		Family string `json:"Family"`
	} `json:"OS"`
}

type vuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Status           string `json:"Status"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	CweIDs []string `json:"CweIDs"`
	CVSS   map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
		V2Score  float64 `json:"V2Score"`
	} `json:"CVSS"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

type misconfig struct {
	Type          string `json:"Type"`
	ID            string `json:"ID"`
	AVDID         string `json:"AVDID"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Message       string `json:"Message"`
	Resolution    string `json:"Resolution"`
	Severity      string `json:"Severity"`
	Status        string `json:"Status"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type license struct {
	Severity string `json:"Severity"`
	PkgName  string `json:"PkgName"`
	FilePath string `json:"FilePath"`
	Name     string `json:"Name"`
}

// Parse streams the findings of a Trivy report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		var artifact, artifactType string
		var meta metadata
		emit := func(rf domain.RawFinding) error {
			if ctx.Err() != nil || !yield(rf, nil) {
				return errStop
			}
			return nil
		}
		err := parseutil.Object(dec, func(key string) error {
			switch key {
			case "ArtifactName":
				return dec.Decode(&artifact)
			case "ArtifactType":
				return dec.Decode(&artifactType)
			case "Metadata":
				return dec.Decode(&meta)
			case "Results":
				return parseutil.Array(dec, func() error {
					return walkResult(dec, artifact, artifactType, meta.OS.Family, emit)
				})
			}
			return parseutil.Skip(dec)
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("trivy: %w", err))
		}
	}
}

func walkResult(dec *json.Decoder, artifact, artifactType, osFamily string, emit func(domain.RawFinding) error) error {
	var res result
	image := ""
	if artifactType == "container_image" {
		image = artifact
	}
	return parseutil.Object(dec, func(key string) error {
		switch key {
		case "Target":
			return dec.Decode(&res.target)
		case "Class":
			return dec.Decode(&res.class)
		case "Type":
			return dec.Decode(&res.typ)
		case "Vulnerabilities":
			return parseutil.Array(dec, func() error {
				var v vuln
				raw, err := parseutil.Element(dec, &v)
				if err != nil {
					return err
				}
				if strings.EqualFold(v.Status, "not_affected") || v.VulnerabilityID == "" {
					return nil
				}
				return emit(mapVuln(v, raw, res, osFamily, image))
			})
		case "Secrets":
			return parseutil.Array(dec, func() error {
				var s secret
				raw, err := parseutil.Element(dec, &s)
				if err != nil {
					return err
				}
				return emit(mapSecret(s, raw, res))
			})
		case "Misconfigurations":
			return parseutil.Array(dec, func() error {
				var m misconfig
				raw, err := parseutil.Element(dec, &m)
				if err != nil {
					return err
				}
				if strings.EqualFold(m.Status, "PASS") { // only what failed is a finding
					return nil
				}
				return emit(mapMisconfig(m, raw, res))
			})
		case "Licenses":
			return parseutil.Array(dec, func() error {
				var l license
				raw, err := parseutil.Element(dec, &l)
				if err != nil {
					return err
				}
				return emit(mapLicense(l, raw, res))
			})
		}
		return parseutil.Skip(dec)
	})
}

func mapVuln(v vuln, raw json.RawMessage, res result, osFamily, image string) domain.RawFinding {
	// The best CVSS: the highest v3 base score of any source.
	var bestScore float64
	var bestVector string
	for _, c := range v.CVSS {
		score := c.V3Score
		if score == 0 {
			score = c.V2Score
		}
		if score > bestScore {
			bestScore, bestVector = score, c.V3Vector
		}
	}
	purl := v.PkgIdentifier.PURL
	if purl == "" {
		purl = derivePurl(res.typ, osFamily, v.PkgName, v.InstalledVersion)
	}
	manifest := ""
	if res.class == "lang-pkgs" {
		manifest = res.target
	}
	loc := domain.Location{Package: parseutil.Package(purl, v.PkgName, v.InstalledVersion, v.FixedVersion, manifest), Image: image}
	title := v.Title
	if title == "" {
		title = fmt.Sprintf("%s: %s", v.PkgName, v.VulnerabilityID)
	}
	return domain.RawFinding{
		ScannerFamily: "trivy", ScannerName: "trivy", Category: domain.CategorySCA,
		RuleID: v.VulnerabilityID, Title: normalize.NFC(title), Description: normalize.NFC(v.Description),
		ToolSeverity: v.Severity, Severity: parseutil.Severity(v.Severity, bestScore),
		VulnIDs: []string{v.VulnerabilityID}, CWEs: parseutil.CWEs(v.CweIDs...), CVSSVector: bestVector,
		Location: loc, RawPayload: raw,
	}
}

func mapSecret(s secret, raw json.RawMessage, res result) domain.RawFinding {
	// Trivy masks the secret in Match; the masked text still tells two secrets of one rule on one line apart.
	return domain.RawFinding{
		ScannerFamily: "trivy", ScannerName: "trivy", Category: domain.CategorySecret,
		RuleID: s.RuleID, Title: normalize.NFC(s.Title), ToolSeverity: s.Severity, Severity: parseutil.Severity(s.Severity, 0),
		SecretValue: s.Match,
		Location:    domain.Location{Code: &domain.CodeLocation{FilePath: normalize.CleanPath(res.target), StartLine: s.StartLine, EndLine: s.EndLine}},
		RawPayload:  raw,
	}
}

func mapMisconfig(m misconfig, raw json.RawMessage, res result) domain.RawFinding {
	id := m.ID
	if id == "" {
		id = m.AVDID
	}
	desc := m.Description
	if m.Message != "" && m.Message != m.Description {
		desc = strings.TrimSpace(m.Message + "\n" + m.Description)
	}
	loc := domain.Location{Code: &domain.CodeLocation{FilePath: normalize.CleanPath(res.target), StartLine: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine}}
	if m.CauseMetadata.Resource != "" {
		loc.Resource = &domain.ResourceLocation{Address: m.CauseMetadata.Resource, Type: m.Type}
	}
	return domain.RawFinding{
		ScannerFamily: "trivy", ScannerName: "trivy", Category: domain.CategoryIaC,
		RuleID: id, RuleName: m.Title, Title: normalize.NFC(m.Title), Description: normalize.NFC(desc),
		ToolSeverity: m.Severity, Severity: parseutil.Severity(m.Severity, 0), Location: loc, RawPayload: raw,
	}
}

func mapLicense(l license, raw json.RawMessage, res result) domain.RawFinding {
	base := "pkg:generic/" + url.PathEscape(l.PkgName)
	return domain.RawFinding{
		ScannerFamily: "trivy", ScannerName: "trivy", Category: domain.CategoryLicense,
		RuleID: l.Name, Title: fmt.Sprintf("%s uses the %s license", l.PkgName, l.Name),
		ToolSeverity: l.Severity, Severity: parseutil.Severity(l.Severity, 0),
		Location:   domain.Location{Package: &domain.PackageLocation{ComponentName: l.PkgName, PurlBase: base, ManifestPath: normalize.CleanPath(firstNonEmpty(l.FilePath, res.target))}},
		RawPayload: raw,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// derivePurl builds a package URL for a package when Trivy did not give one (older report versions): the type
// from the package manager, the namespace from the distribution for OS packages.
func derivePurl(resType, osFamily, name, version string) string {
	typ := parseutil.PurlType(resType)
	if typ == "" || name == "" {
		return ""
	}
	ns := ""
	switch typ {
	case "apk", "deb", "rpm":
		ns = strings.ToLower(osFamily)
	case "maven":
		if g, a, ok := strings.Cut(name, ":"); ok {
			ns, name = g, a
		}
	}
	var b strings.Builder
	b.WriteString("pkg:" + typ + "/")
	if ns != "" {
		b.WriteString(ns + "/")
	}
	b.WriteString(name)
	if version != "" {
		b.WriteString("@" + version)
	}
	return b.String()
}
