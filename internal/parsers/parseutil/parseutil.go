// Package parseutil holds what the native report parsers share: a streaming walk over JSON (docs/16 D15),
// severity normalization with the CVSS fallback (docs/05 section 3), and CWE and package-URL helpers.
package parseutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// MaxDepth is how deep a value may nest before it is refused (docs/16 D15: every parser has a nesting limit).
const MaxDepth = 200

// ErrTooDeep is returned for a document that nests deeper than MaxDepth.
var ErrTooDeep = errors.New("the report nests too deeply")

// Expect reads the next token and requires it to be the delimiter d.
func Expect(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("expected %q, found %v", string(d), tok)
	}
	return nil
}

// Object walks the keys of the JSON object at the decoder's position. For each key, handle must consume the
// value (decode it, walk it, or call Skip).
func Object(dec *json.Decoder, handle func(key string) error) error {
	if err := Expect(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected an object key, found %v", tok)
		}
		if err := handle(key); err != nil {
			return err
		}
	}
	return Expect(dec, '}')
}

// Array walks the elements of the JSON array at the decoder's position; each must consume one element.
// A JSON null is an empty array.
func Array(dec *json.Decoder, each func() error) error {
	if !dec.More() {
		return errors.New("expected an array")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected an array, found %v", tok)
	}
	for dec.More() {
		if err := each(); err != nil {
			return err
		}
	}
	return Expect(dec, ']')
}

// Skip consumes one JSON value without building it, so an unwanted key costs no memory.
func Skip(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > MaxDepth {
					return ErrTooDeep
				}
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// Element decodes one array element and also returns its bytes, which become the finding's raw record.
func Element(dec *json.Decoder, v any) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return raw, err
	}
	return raw, nil
}

// SeverityFromScore maps a CVSS base score to a severity (docs/05 section 3).
func SeverityFromScore(score float64) domain.Severity {
	switch {
	case score >= 9.0:
		return domain.SeverityCritical
	case score >= 7.0:
		return domain.SeverityHigh
	case score >= 4.0:
		return domain.SeverityMedium
	case score > 0:
		return domain.SeverityLow
	}
	return domain.SeverityUnknown
}

// Severity normalizes a tool's severity word, and falls back to the CVSS score when the tool gave none or said
// unknown. "negligible" (Grype) is the lowest rung. A finding with neither stays unknown, which the score treats as low.
func Severity(tool string, cvssScore float64) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "negligible":
		return domain.SeverityInfo
	}
	if s := domain.ParseSeverity(tool); s != domain.SeverityUnknown {
		return s
	}
	return SeverityFromScore(cvssScore)
}

var cweRE = regexp.MustCompile(`(?i)CWE-?(\d{1,5})`)

// CWEs reads CWE ids out of strings such as "CWE-79", "CWE-79: Improper Neutralization..." or "cwe79".
func CWEs(values ...string) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range values {
		for _, m := range cweRE.FindAllStringSubmatch(v, -1) {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// Package builds the package location of an SCA finding: the canonical purl and its version-less base.
func Package(purl, name, installed, fixed, manifest string) *domain.PackageLocation {
	loc := &domain.PackageLocation{ComponentName: normalize.NFC(name), InstalledVersion: installed, FixedVersion: fixed, ManifestPath: normalize.CleanPath(manifest)}
	if canon, base, err := normalize.CanonicalPURL(purl); err == nil && canon != "" {
		loc.Purl, loc.PurlBase = canon, base
	}
	return loc
}

// PurlType maps a package manager or ecosystem name to its package-URL type; "" when unknown.
func PurlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "alpine", "apk":
		return "apk"
	case "debian", "ubuntu", "deb", "dpkg":
		return "deb"
	case "redhat", "centos", "rocky", "alma", "fedora", "oracle", "amazon", "rpm", "suse", "photon":
		return "rpm"
	case "npm", "node-pkg", "yarn", "pnpm", "javascript":
		return "npm"
	case "pip", "pipenv", "poetry", "python-pkg", "python", "pypi":
		return "pypi"
	case "gomod", "gobinary", "go-module", "golang", "go":
		return "golang"
	case "jar", "pom", "gradle", "java-archive", "java", "maven":
		return "maven"
	case "nuget", "dotnet", "dotnet-core":
		return "nuget"
	case "cargo", "rust", "rust-crate":
		return "cargo"
	case "bundler", "gemspec", "ruby", "gem":
		return "gem"
	case "composer", "php":
		return "composer"
	}
	return ""
}
