// Package genericjson parses Rampart's Generic JSON findings format: the format for homegrown tools and tools with
// no parser of their own (docs/05 section 1, docs/01 A10). It is a superset of DefectDojo's "Generic Findings
// Import" JSON, so a DefectDojo export or a script written for DefectDojo loads unchanged. A streaming walk over
// "findings" (docs/16 D15).
//
// # Format
//
//	{
//	  "format":  "rampart-generic/v1",   // optional; marks the document, so auto-detection is certain
//	  "tool":    "my-scanner",           // optional; the tool's name ("name" is read too, as DefectDojo writes it)
//	  "version": "1.2.0",                // optional; the tool's version
//	  "findings": [
//	    {
//	      "title":       "SQL injection in login",          // required
//	      "severity":    "high",                            // critical | high | medium | low | info (any case)
//	      "description": "…",
//	      "mitigation":  "…",                               // also "remediation"; appended to the description
//	      "category":    "sast",                            // sast | sca | secret | iac | container | dast | cspm | compliance | license | supply_chain
//	      "rule_id":     "SQLI-001",                        // also "vuln_id_from_tool"
//	      "id":          "a1b2",                            // the tool's id of this record; also "unique_id_from_tool"
//	      "tool":        "my-scanner",                      // overrides the top-level tool for this finding
//	      "cve":         "CVE-2024-1234",
//	      "vulnerability_ids": ["GHSA-…"],                  // strings, or DefectDojo's [{"vulnerability_id": "…"}]
//	      "cwe":         89,                                // a number, "CWE-89", or a list of either
//	      "cvssv3":      "CVSS:3.1/AV:N/…",                 // also "cvss_vector"
//	      "cvssv3_score": 9.8,                              // also "cvss_score"; used when severity is missing
//	      "file":        "src/login.go",                    // also "file_path"
//	      "line":        42,  "end_line": 44,
//	      "component":   "lodash",                          // also "component_name"
//	      "version":     "4.17.20",                         // also "component_version"
//	      "fixed_version": "4.17.21",
//	      "purl":        "pkg:npm/lodash@4.17.20",
//	      "manifest":    "package-lock.json",
//	      "image":       "registry.example.com/app:1.0",
//	      "url":         "https://app.example.com/login",   // or DefectDojo's "endpoints": ["…"] / [{"protocol","host","port","path","query"}] (the first is used)
//	      "method":      "POST",  "param": "user",
//	      "resource":    "aws_s3_bucket.data",              // a cloud or IaC resource; "resource_type" names its type
//	      "secret":      "…"                                // a found secret: it tells findings apart, is hashed, and is never stored
//	    }
//	  ]
//	}
//
// Every other key is ignored. When "category" is missing it is inferred: a secret makes it secret, a package
// (purl or component) sca, a URL or DefectDojo's "dynamic_finding" dast, a resource without a file cspm, and
// anything else sast. The scanner family is "generic:<tool>" (lower case, spaces as hyphens), or "generic" when no
// tool is named, so two homegrown tools never share finding keys. "tool", "name" and "version" at the top level
// apply to the findings that follow them.
package genericjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/parseutil"
)

// Parser reads Generic JSON findings.
type Parser struct{}

// NewParser returns a Generic JSON parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "generic-json" }

var (
	markerRE   = regexp.MustCompile(`"format"\s*:\s*"rampart-generic(/v1)?"`)
	findingsRE = regexp.MustCompile(`"findings"\s*:\s*\[`)
	// Keys of the reports other parsers read; Generic JSON never claims a document that has them.
	othersRE = regexp.MustCompile(`"(runs|bomFormat|spdxVersion|statements|matches|Results|SchemaVersion|check_id|RuleID|packageManager|vulnerabilities|reportSchema|failed_checks|template-id|CheckID|Controls)"\s*:|"(vulnerability|component|analysis)"\s*:\s*\{`)
)

// Detect scores Generic JSON low (at most 45) so that any real parser that knows the document wins; a document
// that says "format": "rampart-generic/v1" is certain.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	if markerRE.Match(head) {
		return 95
	}
	if !findingsRE.Match(head) || othersRE.Match(head) {
		return 0
	}
	s := string(head)
	score := 25
	if strings.Contains(s, `"title"`) {
		score += 10
	}
	if strings.Contains(s, `"severity"`) {
		score += 10
	}
	if strings.Contains(strings.ToLower(filename), "generic") {
		score += 5
	}
	return min(score, 45)
}

var errStop = errors.New("stop")

// flexInt reads a number or a numeric string.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return err
		}
		n = json.Number(strings.TrimSpace(s))
	}
	if n == "" {
		return nil
	}
	v, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return err
	}
	*f = flexInt(int(v))
	return nil
}

// flexFloat reads a number or a numeric string.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return err
		}
		n = json.Number(strings.TrimSpace(s))
	}
	if n == "" {
		return nil
	}
	v, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return err
	}
	*f = flexFloat(v)
	return nil
}

// strList reads one value or a list of values, each a string, a number or an object with a "vulnerability_id".
type strList []string

func (l *strList) UnmarshalJSON(b []byte) error {
	var items []json.RawMessage
	if json.Unmarshal(b, &items) != nil {
		items = []json.RawMessage{b}
	}
	for _, it := range items {
		var s string
		var n json.Number
		var obj struct {
			VulnerabilityID string `json:"vulnerability_id"`
		}
		switch {
		case json.Unmarshal(it, &s) == nil:
		case json.Unmarshal(it, &n) == nil:
			s = n.String()
		case json.Unmarshal(it, &obj) == nil:
			s = obj.VulnerabilityID
		default:
			return errors.New("expected a string, a number or a list of them")
		}
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

// endpoint is a DefectDojo endpoint: a URL string or its parts.
type endpoint struct{ url string }

func (e *endpoint) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, &e.url) == nil {
		return nil
	}
	var parts struct {
		Protocol string  `json:"protocol"`
		Host     string  `json:"host"`
		Port     flexInt `json:"port"`
		Path     string  `json:"path"`
		Query    string  `json:"query"`
	}
	if err := json.Unmarshal(b, &parts); err != nil {
		return err
	}
	if parts.Host == "" {
		return nil
	}
	u := url.URL{Scheme: parts.Protocol, Host: parts.Host, RawQuery: parts.Query}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if parts.Port > 0 {
		u.Host += ":" + strconv.Itoa(int(parts.Port))
	}
	if parts.Path != "" {
		u.Path = "/" + strings.TrimLeft(parts.Path, "/")
	}
	e.url = u.String()
	return nil
}

type finding struct {
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	Description      string     `json:"description"`
	Mitigation       string     `json:"mitigation"`
	Remediation      string     `json:"remediation"`
	Category         string     `json:"category"`
	RuleID           string     `json:"rule_id"`
	VulnIDFromTool   string     `json:"vuln_id_from_tool"`
	ID               string     `json:"id"`
	UniqueIDFromTool string     `json:"unique_id_from_tool"`
	Tool             string     `json:"tool"`
	CVE              strList    `json:"cve"`
	VulnerabilityIDs strList    `json:"vulnerability_ids"`
	CWE              strList    `json:"cwe"`
	CVSSv3           string     `json:"cvssv3"`
	CVSSVector       string     `json:"cvss_vector"`
	CVSSv3Score      flexFloat  `json:"cvssv3_score"`
	CVSSScore        flexFloat  `json:"cvss_score"`
	File             string     `json:"file"`
	FilePath         string     `json:"file_path"`
	Line             flexInt    `json:"line"`
	EndLine          flexInt    `json:"end_line"`
	Component        string     `json:"component"`
	ComponentName    string     `json:"component_name"`
	Version          string     `json:"version"`
	ComponentVersion string     `json:"component_version"`
	FixedVersion     string     `json:"fixed_version"`
	Purl             string     `json:"purl"`
	Manifest         string     `json:"manifest"`
	Image            string     `json:"image"`
	URL              string     `json:"url"`
	Endpoints        []endpoint `json:"endpoints"`
	Method           string     `json:"method"`
	Param            string     `json:"param"`
	Resource         string     `json:"resource"`
	ResourceType     string     `json:"resource_type"`
	Secret           string     `json:"secret"`
	DynamicFinding   bool       `json:"dynamic_finding"`
}

type header struct{ tool, version string }

// Parse streams the findings of a Generic JSON document.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		var h header
		var name string
		readString := func(dst *string) error {
			var v any
			if err := dec.Decode(&v); err != nil {
				return err
			}
			if s, ok := v.(string); ok {
				*dst = strings.TrimSpace(s)
			}
			return nil
		}
		err := parseutil.Object(dec, func(key string) error {
			switch key {
			case "tool":
				return readString(&h.tool)
			case "name":
				return readString(&name)
			case "version":
				return readString(&h.version)
			case "findings":
				hdr := h
				if hdr.tool == "" {
					hdr.tool = name
				}
				return parseutil.ArrayWith(dec, pc, "findings", func() error {
					var f finding
					raw, err := parseutil.Element(dec, &f)
					if err != nil {
						return err
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if strings.TrimSpace(f.Title) == "" {
						if pc.RecordError != nil {
							return &domain.RecordError{Message: "a finding needs a title"}
						}
						return nil
					}
					if !yield(mapFinding(f, raw, hdr), nil) {
						return errStop
					}
					return nil
				})
			}
			return parseutil.Skip(dec)
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("generic json: %w", err))
		}
	}
}

var knownCategory = map[string]domain.FindingCategory{
	"sast": domain.CategorySAST, "sca": domain.CategorySCA, "secret": domain.CategorySecret, "iac": domain.CategoryIaC,
	"container": domain.CategoryContainer, "dast": domain.CategoryDAST, "cspm": domain.CategoryCSPM,
	"compliance": domain.CategoryCompliance, "license": domain.CategoryLicense, "supply_chain": domain.CategorySupplyChain,
	"supply-chain": domain.CategorySupplyChain,
}

func family(tool string) string {
	t := strings.Join(strings.Fields(strings.ToLower(normalize.NFC(tool))), "-")
	if t == "" {
		return "generic"
	}
	return "generic:" + t
}

func mapFinding(f finding, raw json.RawMessage, h header) domain.RawFinding {
	tool := firstNonEmpty(f.Tool, h.tool)
	file := firstNonEmpty(f.File, f.FilePath)
	component := firstNonEmpty(f.Component, f.ComponentName)
	webURL := strings.TrimSpace(f.URL)
	for _, e := range f.Endpoints {
		if webURL == "" {
			webURL = e.url
		}
	}

	cat, ok := knownCategory[strings.ToLower(strings.TrimSpace(f.Category))]
	if !ok {
		switch {
		case f.Secret != "":
			cat = domain.CategorySecret
		case f.Purl != "" || component != "":
			cat = domain.CategorySCA
		case webURL != "" || f.DynamicFinding:
			cat = domain.CategoryDAST
		case f.Resource != "" && file == "":
			cat = domain.CategoryCSPM
		default:
			cat = domain.CategorySAST
		}
	}

	vulnIDs := append(append([]string{}, f.CVE...), f.VulnerabilityIDs...)
	ruleID := firstNonEmpty(f.RuleID, f.VulnIDFromTool)
	if ruleID == "" && len(vulnIDs) > 0 {
		ruleID = normalize.CanonicalVulnID(vulnIDs)
	}
	if ruleID == "" {
		ruleID = f.Title // a homegrown tool may give nothing else to tell its checks apart
	}
	score := float64(f.CVSSv3Score)
	if score == 0 {
		score = float64(f.CVSSScore)
	}
	desc := strings.TrimSpace(f.Description)
	if m := firstNonEmpty(f.Mitigation, f.Remediation); m != "" {
		desc = strings.TrimSpace(desc + "\n\nMitigation: " + m)
	}
	cwes := make([]string, 0, len(f.CWE))
	for _, c := range f.CWE {
		if _, err := strconv.Atoi(c); err == nil {
			c = "CWE-" + c
		}
		cwes = append(cwes, c)
	}

	rf := domain.RawFinding{
		ScannerFamily: family(tool), ScannerName: firstNonEmpty(tool, "generic"), ScannerVersion: h.version, Category: cat,
		ToolRecordID: firstNonEmpty(f.ID, f.UniqueIDFromTool), RuleID: ruleID, Title: normalize.NFC(strings.TrimSpace(f.Title)),
		Description: normalize.NFC(desc), ToolSeverity: f.Severity, Severity: parseutil.Severity(f.Severity, score),
		VulnIDs: vulnIDs, CWEs: parseutil.CWEs(cwes...), CVSSVector: firstNonEmpty(f.CVSSv3, f.CVSSVector), RawPayload: raw,
	}
	if cat == domain.CategorySCA && len(rf.VulnIDs) == 0 {
		rf.VulnIDs = []string{ruleID}
	}

	loc := domain.Location{Image: strings.TrimSpace(f.Image)}
	if file != "" {
		loc.Code = &domain.CodeLocation{FilePath: normalize.CleanPath(file), StartLine: int(f.Line), EndLine: int(f.EndLine)}
	}
	if f.Purl != "" || component != "" {
		loc.Package = parseutil.Package(f.Purl, component, firstNonEmpty(f.Version, f.ComponentVersion), f.FixedVersion, firstNonEmpty(f.Manifest, file))
		if loc.Package.PurlBase == "" && component != "" && f.Purl == "" {
			loc.Package.PurlBase = "pkg:generic/" + url.PathEscape(component)
		}
	}
	if webURL != "" || f.Method != "" || f.Param != "" {
		loc.Web = &domain.WebLocation{NormalizedURL: webURL, Method: strings.ToUpper(strings.TrimSpace(f.Method)), Parameter: f.Param}
	}
	if f.Resource != "" {
		loc.Resource = &domain.ResourceLocation{Address: f.Resource, Key: f.Resource, Type: f.ResourceType}
	}
	rf.Location = loc

	if f.Secret != "" {
		rf.SecretValue = f.Secret
		rf.RawPayload = redact(raw)
	}
	return rf
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// redact removes the secret from a record before it is stored.
func redact(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil // an unreadable record is not stored: it might hold the secret
	}
	if _, ok := m["secret"]; ok {
		m["secret"] = "[redacted]"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}
