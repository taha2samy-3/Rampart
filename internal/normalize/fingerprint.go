package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// UnitSeparator is ASCII byte 0x1F per normative D11.
const UnitSeparator = byte(0x1F)

// ScopeType represents the deduplication boundary (D11).
type ScopeType string

const (
	ScopeAsset       ScopeType = "asset"       // Default: tenant_id US asset_id US track
	ScopeApplication ScopeType = "application" // tenant_id US application_id
	ScopeTenant      ScopeType = "tenant"      // tenant_id
)

// FingerprintResult captures the derived key and whether fallback heuristics were applied.
type FingerprintResult struct {
	FindingKey      string
	WeakFingerprint bool
	// LineageKey is the finding key with the track left out: the same issue on another branch or environment of
	// the same asset has the same LineageKey (D57). Empty for a weak fingerprint, whose identity is too loose to
	// carry a decision on.
	LineageKey string
}

// FingerprintParams holds all inputs required to compute a finding key.
type FingerprintParams struct {
	TenantID      uuid.UUID
	AssetID       uuid.UUID
	ApplicationID uuid.UUID
	Track         string
	Scope         ScopeType
	Family        string
	Category      domain.FindingCategory
	RuleID        string
	RawFinding    domain.RawFinding
}

// ComputeFingerprint implements the normative D11 deterministic fingerprint algorithm.
// finding_key = SHA-256( "v1" US family US scope_key US f1 US f2 … )
func ComputeFingerprint(params FingerprintParams) FingerprintResult {
	family := NFC(params.Family)
	if family == "" {
		family = CanonicalScannerFamily(params.RawFinding.ScannerFamily)
	}

	scopeKey := buildScopeKey(params)

	var fields []string
	var isWeak bool

	loc := params.RawFinding.Location

	switch params.Category {
	case domain.CategorySAST:
		// SAST: rule_id, file_path, first non-empty of (logical_location, snippet_hash, primaryLocationLineHash)
		ruleID := NFC(params.RuleID)
		filePath := ""
		discrim := ""
		startLine := ""

		if loc.Code != nil {
			filePath = CleanPath(loc.Code.FilePath)
			if loc.Code.LogicalLocation != "" {
				discrim = NFC(loc.Code.LogicalLocation)
			} else if loc.Code.SnippetHash != "" {
				discrim = loc.Code.SnippetHash
			} else if loc.Code.Snippet != "" {
				discrim = ComputeSnippetHash(loc.Code.Snippet)
			}
			if loc.Code.StartLine > 0 {
				startLine = strconv.Itoa(loc.Code.StartLine)
			}
		}

		if discrim == "" && startLine != "" {
			discrim = startLine
			isWeak = true
		}

		fields = []string{ruleID, filePath, discrim}

	case domain.CategorySCA:
		// SCA: canonical_vuln_id, purl_base, manifest_path (or image_repository)
		vulnID := NFC(CanonicalVulnID(params.RawFinding.VulnIDs)) // the CVE when there is one (D11)
		purlBase := ""
		manifest := ""
		if loc.Package != nil {
			purlBase = NFC(loc.Package.PurlBase)
			manifest = CleanPath(loc.Package.ManifestPath)
			if purlBase == "" && loc.Package.ComponentName != "" {
				purlBase = NFC(loc.Package.ComponentName)
				isWeak = true
			}
		}
		fields = []string{vulnID, purlBase, manifest}

	case domain.CategorySecret:
		// Secret: rule_id, file_path, secret_hash (fallback: start_line)
		ruleID := NFC(params.RuleID)
		filePath := ""
		secretHash := ""
		startLine := ""

		if loc.Code != nil {
			filePath = CleanPath(loc.Code.FilePath)
			if loc.Code.SnippetHash != "" {
				secretHash = loc.Code.SnippetHash
			}
			if loc.Code.StartLine > 0 {
				startLine = strconv.Itoa(loc.Code.StartLine)
			}
		}
		if secretHash == "" && params.RawFinding.SecretValue != "" {
			secretHash = ComputeSecretHash(params.RawFinding.SecretValue)
		}
		if secretHash == "" && startLine != "" {
			secretHash = startLine
			isWeak = true
		}
		fields = []string{ruleID, filePath, secretHash}

	case domain.CategoryIaC:
		// IaC: rule_id, file_path, resource_address (fallback: start_line)
		ruleID := NFC(params.RuleID)
		filePath := ""
		address := ""
		startLine := ""

		if loc.Code != nil {
			filePath = CleanPath(loc.Code.FilePath)
			if loc.Code.StartLine > 0 {
				startLine = strconv.Itoa(loc.Code.StartLine)
			}
		}
		if loc.Resource != nil && loc.Resource.Address != "" {
			address = NFC(loc.Resource.Address)
		}
		if address == "" && startLine != "" {
			address = startLine
			isWeak = true
		}
		fields = []string{ruleID, filePath, address}

	case domain.CategoryCompliance, domain.CategoryCSPM:
		// Config / Compliance: control_id or rule_id, resource_key
		ruleID := NFC(params.RuleID)
		resourceKey := ""
		if loc.Resource != nil {
			resourceKey = NFC(loc.Resource.Key)
		}
		fields = []string{ruleID, resourceKey}

	case domain.CategoryDAST:
		// DAST: rule_id, normalized_url, method, param
		ruleID := NFC(params.RuleID)
		normURL := ""
		method := ""
		param := ""
		if loc.Web != nil {
			normURL = NormalizeURL(loc.Web.NormalizedURL)
			method = strings.ToUpper(NFC(loc.Web.Method))
			param = NFC(loc.Web.Parameter)
		}
		fields = []string{ruleID, normURL, method, param}

	case domain.CategoryLicense:
		// License: purl_base, license_id
		purlBase := ""
		if loc.Package != nil {
			purlBase = NFC(loc.Package.PurlBase)
		}
		licenseID := NFC(params.RuleID)
		fields = []string{purlBase, licenseID}

	default:
		// Generic fallback
		ruleID := NFC(params.RuleID)
		pathOrLoc := NFC(loc.PrimaryPath())
		fields = []string{ruleID, pathOrLoc}
	}

	// Check if all fields are empty
	allEmpty := true
	for _, f := range fields {
		if f != "" {
			allEmpty = false
			break
		}
	}

	if allEmpty {
		// D11 fallback: hash of raw payload, marked as weak
		isWeak = true
		if len(params.RawFinding.RawPayload) > 0 {
			h := sha256.Sum256(params.RawFinding.RawPayload)
			return FingerprintResult{
				FindingKey:      hex.EncodeToString(h[:]),
				WeakFingerprint: true,
			}
		}
	}

	// Compute serialization: "v1" US family US scope_key US f1 US f2 ...
	h := sha256.New()
	h.Write([]byte("v1"))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(family))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(scopeKey))

	for _, f := range fields {
		h.Write([]byte{UnitSeparator})
		h.Write([]byte(f))
	}

	digest := hex.EncodeToString(h.Sum(nil))
	res := FingerprintResult{FindingKey: digest, WeakFingerprint: isWeak, LineageKey: digest}
	if isWeak {
		res.LineageKey = ""
	} else if params.Scope != ScopeTenant && params.Scope != ScopeApplication {
		// "v1-lineage" US family US tenant US asset US f1 … : D11's key with the track removed from the scope.
		l := sha256.New()
		l.Write([]byte("v1-lineage"))
		l.Write([]byte{UnitSeparator})
		l.Write([]byte(family))
		l.Write([]byte{UnitSeparator})
		_, _ = fmt.Fprintf(l, "%s%c%s", params.TenantID.String(), UnitSeparator, params.AssetID.String())
		for _, f := range fields {
			l.Write([]byte{UnitSeparator})
			l.Write([]byte(f))
		}
		res.LineageKey = hex.EncodeToString(l.Sum(nil))
	}
	return res
}

func buildScopeKey(p FingerprintParams) string {
	switch p.Scope {
	case ScopeTenant:
		return p.TenantID.String()
	case ScopeApplication:
		return fmt.Sprintf("%s%c%s", p.TenantID.String(), UnitSeparator, p.ApplicationID.String())
	default: // ScopeAsset
		track := NFC(p.Track)
		if track == "" {
			track = "default"
		}
		return fmt.Sprintf("%s%c%s%c%s", p.TenantID.String(), UnitSeparator, p.AssetID.String(), UnitSeparator, track)
	}
}

// ComputeContentHash computes SHA-256 over fields that a rescan may legitimately change (D13).
// It defines whether an existing finding is classified as "updated" vs "untouched".
func ComputeContentHash(title, description, toolSeverity, cvssVector, fixedVersion, primaryPath string) string {
	h := sha256.New()
	h.Write([]byte(NFC(title)))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(NFC(description)))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(NFC(toolSeverity)))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(NFC(cvssVector)))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(NFC(fixedVersion)))
	h.Write([]byte{UnitSeparator})
	h.Write([]byte(CleanPath(primaryPath)))
	return hex.EncodeToString(h.Sum(nil))
}
