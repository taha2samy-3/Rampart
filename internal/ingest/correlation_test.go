package ingest_test

import (
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func scaRec(vuln, purl string) ingest.StagedRecord {
	return ingest.StagedRecord{Category: domain.CategorySCA, VulnID: vuln, Location: domain.Location{Package: &domain.PackageLocation{PurlBase: purl}}}
}

func TestCorrelationKey(t *testing.T) {
	asset, other := uuid.New(), uuid.New()
	a := ingest.CorrelationKey(scaRec("CVE-2024-1", "pkg:npm/x"), "CVE-2024-1", asset, "main")
	if a == "" {
		t.Fatal("an SCA finding with a CVE and a package must have a key")
	}
	// Two tools, same issue, same asset: same key. The vulnerability id is compared case-insensitively.
	if b := ingest.CorrelationKey(scaRec("cve-2024-1", "pkg:npm/x"), "cve-2024-1", asset, "main"); a != b {
		t.Fatal("the same issue reported by two tools must share a key")
	}
	// An alias resolved to its CVE correlates with the CVE report (D11, D24).
	if c := ingest.CorrelationKey(scaRec("GHSA-aaaa", "pkg:npm/x"), "CVE-2024-1", asset, "main"); a != c {
		t.Fatal("a GHSA finding must correlate with its CVE once the alias is resolved")
	}
	for name, k := range map[string]string{
		"other asset":   ingest.CorrelationKey(scaRec("CVE-2024-1", "pkg:npm/x"), "CVE-2024-1", other, "main"),
		"other track":   ingest.CorrelationKey(scaRec("CVE-2024-1", "pkg:npm/x"), "CVE-2024-1", asset, "dev"),
		"other package": ingest.CorrelationKey(scaRec("CVE-2024-1", "pkg:npm/y"), "CVE-2024-1", asset, "main"),
		"other vuln":    ingest.CorrelationKey(scaRec("CVE-2024-2", "pkg:npm/x"), "CVE-2024-2", asset, "main"),
	} {
		if k == a {
			t.Fatalf("%s must not correlate", name)
		}
	}
	if ingest.CorrelationKey(scaRec("", "pkg:npm/x"), "", asset, "main") != "" {
		t.Fatal("no vulnerability id: no key")
	}
	sast := func(cwe int, file, fn string) string {
		return ingest.CorrelationKey(ingest.StagedRecord{Category: domain.CategorySAST, CWEs: []int{cwe},
			Location: domain.Location{Code: &domain.CodeLocation{FilePath: file, LogicalLocation: fn}}}, "", asset, "main")
	}
	run, again, differs := sast(89, "a.go", "Run"), sast(89, "a.go", "Run"), sast(89, "a.go", "Other")
	if run == "" || run != again || run == differs {
		t.Fatal("SAST correlates on CWE + file + function")
	}
	if sast(0, "a.go", "Run") != "" {
		t.Fatal("no CWE: no key")
	}
}
