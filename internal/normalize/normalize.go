package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/text/unicode/norm"
)

var whitespaceRegex = regexp.MustCompile(`\s+`)

// NFC trims and normalizes a UTF-8 string to Unicode Normalization Form C (D11).
func NFC(s string) string {
	return norm.NFC.String(strings.TrimSpace(s))
}

// CleanPath standardizes repository and file paths: resolves forward slashes, strips leading './'.
func CleanPath(p string) string {
	clean := strings.ReplaceAll(p, "\\", "/")
	clean = strings.TrimPrefix(clean, "./")
	clean = path.Clean(clean)
	if clean == "." {
		return ""
	}
	return NFC(clean)
}

// NormalizeURL strips query parameters and fragment to derive a stable DAST URL target (D11).
func NormalizeURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return NFC(rawURL)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return NFC(u.String())
}

// ComputeSnippetHash derives a deterministic hash over whitespace-normalized code snippets (D11).
func ComputeSnippetHash(snippet string) string {
	trimmed := strings.TrimSpace(snippet)
	if trimmed == "" {
		return ""
	}
	normalized := whitespaceRegex.ReplaceAllString(trimmed, " ")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// ComputeSecretHash derives the SHA-256 digest of an exposed secret value (D11).
func ComputeSecretHash(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(hash[:])
}

// CanonicalScannerFamily normalizes scanner names per normative D11.
func CanonicalScannerFamily(toolDriverName string) string {
	name := strings.ToLower(strings.TrimSpace(toolDriverName))
	switch name {
	case "semgrep":
		return "semgrep"
	case "codeql":
		return "codeql"
	case "trivy":
		return "trivy"
	case "grype":
		return "grype"
	case "gitleaks":
		return "gitleaks"
	case "checkov":
		return "checkov"
	case "bandit":
		return "bandit"
	case "nuclei":
		return "nuclei"
	case "snyk":
		return "snyk"
	case "zap", "owasp zap":
		return "zap"
	case "kics":
		return "kics"
	case "dependency-check":
		return "dependency-check"
	case "osv-scanner":
		return "osv-scanner"
	case "scorecard":
		return "scorecard"
	case "hadolint":
		return "hadolint"
	default:
		if name == "" {
			return "sarif:unknown"
		}
		return "sarif:" + name
	}
}

// CanonicalPURL parses a raw Package URL, re-serializes canonically, and derives purl_base without version/qualifiers (docs/05 §3).
func CanonicalPURL(raw string) (canonical string, purlBase string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", nil
	}

	p, err := packageurl.FromString(trimmed)
	if err != nil {
		// Fallback for non-standard PURLs: strip '@' version and '?' qualifiers
		base := trimmed
		if idx := strings.Index(base, "?"); idx != -1 {
			base = base[:idx]
		}
		if idx := strings.Index(base, "@"); idx != -1 {
			base = base[:idx]
		}
		return trimmed, base, nil
	}

	canonical = p.ToString()

	// Derive purl_base by removing version, qualifiers and subpath
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""
	purlBase = p.ToString()

	return canonical, purlBase, nil
}
