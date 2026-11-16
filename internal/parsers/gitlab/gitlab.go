// Package gitlab parses GitLab security reports (security-report-schemas v14 and v15): gl-sast-report.json,
// gl-secret-detection-report.json, gl-dependency-scanning-report.json, gl-container-scanning-report.json and
// gl-dast-report.json (also api_fuzzing, coverage_fuzzing and cluster_image_scanning, which share the layouts).
// A streaming walk over "vulnerabilities" (docs/16 D15).
//
// GitLab analyzers write "scan" after "vulnerabilities", so the scan type is usually not known while the findings
// stream. The kind of each finding is therefore read from its own location, which every report type shapes
// differently (a file and lines, a dependency, a dependency in an image, a host and path, a commit); scan.type is
// used when it came first. The scanner family is "gitlab-<report type>" (gitlab-sast, gitlab-secret-detection,
// gitlab-dependency-scanning, gitlab-container-scanning, gitlab-dast): GitLab rewrites the rule identifiers of the
// tools it wraps, so its findings do not share keys with the native parsers, and one family per report type keeps
// a SAST upload from closing the dependency findings of the same pipeline.
//
// A secret found by secret detection is used to tell findings apart (hashed by the pipeline) and never stored:
// raw_source_code_extract is removed from the raw record.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/parseutil"
)

// Parser reads GitLab security reports.
type Parser struct{}

// NewParser returns a GitLab security report parser.
func NewParser() *Parser { return &Parser{} }

// Name identifies the parser.
func (p *Parser) Name() string { return "gitlab-security-report" }

// Detect scores how likely head is a GitLab security report: a "vulnerabilities" array whose items carry an
// "identifiers" array, with "scan" (often at the end, past the head) and the schema URL as extra signs.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	s := string(head)
	if strings.Contains(s, `"runs"`) || strings.Contains(s, `"bomFormat"`) || strings.Contains(s, `"spdxVersion"`) ||
		strings.Contains(s, `"packageManager"`) { // SARIF, CycloneDX, SPDX, Snyk
		return 0
	}
	score := 0
	if strings.Contains(s, `"vulnerabilities"`) && strings.Contains(s, `"identifiers"`) {
		score += 40
	}
	if strings.Contains(s, `"scan"`) && (strings.Contains(s, `"analyzer"`) || strings.Contains(s, `"scanner"`)) {
		score += 25
	}
	if strings.Contains(s, "security-report-schemas") {
		score += 20
	}
	if strings.Contains(s, `"location"`) {
		score += 10
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(filename, `\`, "/")))
	if strings.HasPrefix(base, "gl-") && strings.HasSuffix(base, "-report.json") {
		score += 30
	}
	return min(score, 100)
}

var errStop = errors.New("stop")

type identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}

type vulnerability struct {
	ID          string       `json:"id"`
	Category    string       `json:"category"` // v14 and earlier; removed in v15
	Name        string       `json:"name"`
	Message     string       `json:"message"` // v14 and earlier
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Solution    string       `json:"solution"`
	Identifiers []identifier `json:"identifiers"`
	CVSSVectors []struct {
		Vendor string `json:"vendor"`
		Vector string `json:"vector"`
	} `json:"cvss_vectors"`
	Scanner *struct { // v14 and earlier
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"scanner"`
	Location struct {
		// sast, secret_detection, dependency_scanning (the manifest), coverage_fuzzing
		File      string `json:"file"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Class     string `json:"class"`
		Method    string `json:"method"` // the function (sast) or the HTTP method (dast)
		// secret_detection
		Commit *struct {
			SHA string `json:"sha"`
		} `json:"commit"`
		// dependency_scanning, container_scanning
		Dependency *struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		} `json:"dependency"`
		OperatingSystem string `json:"operating_system"`
		Image           string `json:"image"`
		// dast, api_fuzzing
		Hostname string `json:"hostname"`
		Path     string `json:"path"`
		Param    string `json:"param"`
		// coverage_fuzzing
		CrashType string `json:"crash_type"`
	} `json:"location"`
	Tracking *struct {
		Items []struct {
			Signatures []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"signatures"`
		} `json:"items"`
	} `json:"tracking"`
	RawSourceCodeExtract string `json:"raw_source_code_extract"`
}

type scan struct {
	Type    string `json:"type"`
	Scanner struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"scanner"`
}

// Parse streams the findings of a GitLab security report.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)
		var sc *scan
		err := parseutil.Object(dec, func(key string) error {
			switch key {
			case "scan":
				var s scan
				if err := dec.Decode(&s); err != nil {
					return err
				}
				sc = &s
				return nil
			case "vulnerabilities":
				return parseutil.ArrayWith(dec, pc, "vulnerabilities", func() error {
					var v vulnerability
					raw, err := parseutil.Element(dec, &v)
					if err != nil {
						return err
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if len(v.Identifiers) == 0 && v.Name == "" && v.Message == "" {
						return nil // nothing to name it by
					}
					if !yield(mapVulnerability(v, raw, sc), nil) {
						return errStop
					}
					return nil
				})
			}
			return parseutil.Skip(dec)
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(domain.RawFinding{}, fmt.Errorf("gitlab: %w", err))
		}
	}
}

// kind is the report type of a finding: scan.type when it is known, else read from the finding.
func kind(v vulnerability, sc *scan) string {
	t := ""
	if sc != nil {
		t = strings.ToLower(sc.Type)
	}
	if t == "" {
		t = strings.ToLower(v.Category)
	}
	switch t {
	case "sast", "coverage_fuzzing":
		return "sast"
	case "secret_detection":
		return "secret-detection"
	case "dependency_scanning":
		return "dependency-scanning"
	case "container_scanning", "container_scanning_for_registry", "cluster_image_scanning":
		return "container-scanning"
	case "dast", "api_fuzzing":
		return "dast"
	}
	loc := v.Location
	switch {
	case loc.Dependency != nil && (loc.Image != "" || loc.OperatingSystem != ""):
		return "container-scanning"
	case loc.Dependency != nil:
		return "dependency-scanning"
	case loc.Hostname != "" || (loc.Path != "" && loc.File == ""):
		return "dast"
	case loc.Commit != nil || v.RawSourceCodeExtract != "" || hasIdentifier(v, "gitleaks_rule_id"):
		return "secret-detection"
	}
	return "sast"
}

func hasIdentifier(v vulnerability, typ string) bool {
	for _, id := range v.Identifiers {
		if strings.EqualFold(id.Type, typ) {
			return true
		}
	}
	return false
}

func mapVulnerability(v vulnerability, raw json.RawMessage, sc *scan) domain.RawFinding {
	k := kind(v, sc)
	rf := domain.RawFinding{
		ScannerFamily: "gitlab-" + k, ScannerName: "gitlab", ToolRecordID: v.ID,
		ToolSeverity: v.Severity, Severity: parseutil.Severity(v.Severity, 0), RawPayload: raw,
	}
	if sc != nil && sc.Scanner.ID != "" {
		rf.ScannerName, rf.ScannerVersion = sc.Scanner.ID, sc.Scanner.Version
	} else if v.Scanner != nil && v.Scanner.ID != "" {
		rf.ScannerName = v.Scanner.ID
	}

	// The first identifier is the primary one (GitLab's rule); CVE and GHSA ids name the vulnerability, CWE ids
	// the weakness.
	var cweStrings []string
	for i, id := range v.Identifiers {
		val := strings.TrimSpace(id.Value)
		if i == 0 {
			rf.RuleID, rf.RuleName = val, id.Name
		}
		switch strings.ToLower(id.Type) {
		case "cve", "ghsa", "osv":
			if val != "" {
				rf.VulnIDs = append(rf.VulnIDs, val)
			}
		case "cwe":
			cweStrings = append(cweStrings, "CWE-"+strings.TrimPrefix(strings.ToUpper(val), "CWE-"), id.Name)
		}
	}
	rf.CWEs = parseutil.CWEs(cweStrings...)
	for _, c := range v.CVSSVectors {
		if c.Vector != "" {
			rf.CVSSVector = c.Vector
			break
		}
	}

	title := firstNonEmpty(v.Name, v.Message, rf.RuleName, rf.RuleID)
	rf.Title = normalize.NFC(title)
	desc := firstNonEmpty(v.Description, v.Message)
	if s := strings.TrimSpace(v.Solution); s != "" {
		desc = strings.TrimSpace(desc + "\n\nSolution: " + s)
	}
	rf.Description = normalize.NFC(desc)

	loc := v.Location
	switch k {
	case "dependency-scanning", "container-scanning":
		rf.Category = domain.CategorySCA
		if len(rf.VulnIDs) == 0 && rf.RuleID != "" {
			rf.VulnIDs = []string{rf.RuleID} // a Gemnasium advisory without a CVE
		}
		name, version := "", ""
		if loc.Dependency != nil {
			name, version = loc.Dependency.Package.Name, loc.Dependency.Version
		}
		manifest := ""
		var purl string
		if k == "dependency-scanning" {
			manifest = loc.File
			purl = buildPurl(ecosystemOfManifest(loc.File), "", name, version)
		} else {
			distro, _, _ := strings.Cut(strings.TrimSpace(loc.OperatingSystem), " ") // "alpine 3.18.4"
			purl = buildPurl(parseutil.PurlType(distro), strings.ToLower(distro), name, version)
			rf.Location.Image = loc.Image
		}
		rf.Location.Package = parseutil.Package(purl, name, version, "", manifest)
	case "dast":
		rf.Category = domain.CategoryDAST
		rf.Location.Web = &domain.WebLocation{NormalizedURL: joinURL(loc.Hostname, loc.Path), Method: strings.ToUpper(loc.Method), Parameter: loc.Param}
		rf.RawPayload = redactCredentials(raw)
	case "secret-detection":
		rf.Category = domain.CategorySecret
		rf.Location.Code = &domain.CodeLocation{FilePath: normalize.CleanPath(loc.File), StartLine: loc.StartLine, EndLine: loc.EndLine}
		rf.SecretValue = strings.TrimSpace(v.RawSourceCodeExtract)
		if rf.SecretValue == "" {
			rf.SecretValue = signature(v) // older reports: GitLab's own hash of the line tells two secrets apart
		}
		rf.RawPayload = redact(raw)
	default:
		rf.Category = domain.CategorySAST
		code := &domain.CodeLocation{FilePath: normalize.CleanPath(loc.File), StartLine: loc.StartLine, EndLine: loc.EndLine}
		if loc.CrashType == "" { // a fuzzing crash has no class or method
			code.LogicalLocation = strings.Trim(loc.Class+"."+loc.Method, ".")
		}
		if code.LogicalLocation == "" {
			if sig := signature(v); sig != "" {
				// GitLab's tracking signature survives code moving, as a snippet hash does.
				code.SnippetHash = normalize.ComputeSnippetHash(sig)
			}
		}
		rf.Location.Code = code
	}
	return rf
}

// signature is the strongest tracking signature GitLab gave (its own order: scope_offset_compressed, scope_offset,
// hash), as "algorithm:value"; "" when there is none.
func signature(v vulnerability) string {
	if v.Tracking == nil {
		return ""
	}
	best, bestRank := "", 0
	for _, item := range v.Tracking.Items {
		for _, s := range item.Signatures {
			rank := map[string]int{"scope_offset_compressed": 3, "scope_offset": 2, "hash": 1}[s.Algorithm]
			if rank > bestRank && s.Value != "" {
				best, bestRank = s.Algorithm+":"+s.Value, rank
			}
		}
	}
	return best
}

// ecosystemOfManifest names the package-URL type of a dependency-scanning manifest or lock file.
func ecosystemOfManifest(file string) string {
	switch strings.ToLower(path.Base(strings.ReplaceAll(file, `\`, "/"))) {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "package.json":
		return "npm"
	case "go.sum", "go.mod", "go.graph":
		return "golang"
	case "pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts", "build.sbt", "maven-dependencies.json", "dependencies.lock":
		return "maven"
	case "requirements.txt", "requirements.pip", "pipfile.lock", "pipdeptree.json", "poetry.lock", "setup.py", "uv.lock":
		return "pypi"
	case "gemfile.lock", "gems.locked":
		return "gem"
	case "composer.lock":
		return "composer"
	case "packages.lock.json":
		return "nuget"
	case "cargo.lock":
		return "cargo"
	case "conan.lock":
		return "conan"
	}
	return ""
}

// buildPurl makes a package URL from the package name GitLab gives ("group/artifact" for Maven, "@scope/name" for
// npm); "" when the type is not known.
func buildPurl(typ, namespace, name, version string) string {
	name = strings.TrimSpace(name)
	if typ == "" || name == "" {
		return ""
	}
	switch typ {
	case "maven", "npm", "golang", "composer":
		if i := strings.LastIndex(name, "/"); i > 0 {
			namespace, name = name[:i], name[i+1:]
		}
	}
	return packageurl.NewPackageURL(typ, namespace, name, version, nil, "").ToString()
}

func joinURL(host, p string) string {
	if host == "" {
		return p
	}
	if p == "" {
		return host
	}
	return strings.TrimRight(host, "/") + "/" + strings.TrimLeft(p, "/")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// redact removes the secret from a secret-detection record before it is stored.
func redact(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil // an unreadable record is not stored: it might hold the secret
	}
	if _, ok := m["raw_source_code_extract"]; ok {
		m["raw_source_code_extract"] = "[redacted]"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}

// sensitiveHeaders are the HTTP headers whose values are credentials; DAST evidence records whole requests.
var sensitiveHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true, "x-api-key": true}

// redactCredentials blanks the credential headers of the requests and responses in a DAST record's evidence.
func redactCredentials(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	ev, ok := m["evidence"].(map[string]any)
	if !ok {
		return raw
	}
	exchanges := []any{ev}
	if sup, ok := ev["supporting_messages"].([]any); ok {
		exchanges = append(exchanges, sup...)
	}
	for _, x := range exchanges {
		xm, ok := x.(map[string]any)
		if !ok {
			continue
		}
		for _, side := range []string{"request", "response"} {
			msg, ok := xm[side].(map[string]any)
			if !ok {
				continue
			}
			headers, _ := msg["headers"].([]any)
			for _, h := range headers {
				if hm, ok := h.(map[string]any); ok {
					if name, _ := hm["name"].(string); sensitiveHeaders[strings.ToLower(name)] {
						hm["value"] = "[redacted]"
					}
				}
			}
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}
