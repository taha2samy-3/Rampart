package sbom

import (
	"fmt"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// FamilyPrefix starts the scanner family of the findings a reader extracts from a document ("sbom-cyclonedx"). It is
// its own family, so a rescan of the document closes only what the document stated before, and never a finding of a
// scanner or of the matcher (D131).
const FamilyPrefix = "sbom-"

// findingsOf turns the vulnerabilities of a document into findings, one for each (vulnerability, component).
//
// A finding is made only from what the document states. The CPE of a component is never used: it names a product, not a
// package, and matching on it is a guess. A vulnerability that names no component of the document is a record error.
func findingsOf(res *Result, format string, pc domain.ParseContext) []domain.RawFinding {
	if len(res.Vulnerabilities) == 0 {
		return nil
	}
	byKey := make(map[string]*domain.SBOMComponent, 2*len(res.Components))
	for i := range res.Components {
		c := &res.Components[i]
		if c.Ref != "" {
			byKey[c.Ref] = c
		}
		if c.Purl != "" {
			if _, taken := byKey[c.Purl]; !taken {
				byKey[c.Purl] = c
			}
		}
	}

	family := FamilyPrefix + normalizeFormat(format)
	var out []domain.RawFinding
	for _, v := range res.Vulnerabilities {
		c := byKey[v.AffectedRef]
		if c == nil {
			if pc.RecordError != nil {
				pc.RecordError(domain.RecordError{
					Where:   "vulnerability " + v.ID,
					Message: fmt.Sprintf("it affects %q, which is not a component of the document", v.AffectedRef),
				})
			}
			continue
		}
		purl, base := c.Purl, c.PurlBase
		if canon, b, err := normalize.CanonicalPURL(c.Purl); err == nil && canon != "" {
			purl, base = canon, b
		}
		desc := strings.TrimSpace(v.Description)
		if d := strings.TrimSpace(v.Detail); d != "" && d != desc {
			if desc != "" {
				desc += "\n\n"
			}
			desc += d
		}
		ids := append([]string{v.ID}, v.Aliases...)
		out = append(out, domain.RawFinding{
			ScannerFamily: family, ScannerName: family, Category: domain.CategorySCA,
			RuleID: v.ID, Title: normalize.NFC(fmt.Sprintf("%s: %s", c.Name, v.ID)), Description: normalize.NFC(desc),
			ToolSeverity: v.Severity, Severity: severityOf(v.Severity, v.Score),
			CWEs: v.CWEs, VulnIDs: ids, CVSSVector: v.Vector,
			Location: domain.Location{Package: &domain.PackageLocation{
				Purl: purl, PurlBase: base, ComponentName: normalize.NFC(c.Name), InstalledVersion: c.Version,
			}},
		})
	}
	return out
}

// severityOf is the severity of a statement: its own word when it has a known one, else the band of its score.
func severityOf(word string, score float64) domain.Severity {
	if s := domain.ParseSeverity(word); s != domain.SeverityUnknown {
		return s
	}
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
