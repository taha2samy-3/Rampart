package normalize_test

import (
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

func TestSASTFingerprintStabilityAcrossLineChanges(t *testing.T) {
	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()

	// Finding at line 42 with a snippet
	rawFinding1 := domain.RawFinding{
		ScannerFamily: "semgrep",
		Category:      domain.CategorySAST,
		RuleID:        "rules.security.sql_injection",
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  "services/auth/db.go",
				StartLine: 42,
				Snippet:   "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))",
			},
		},
	}

	// Rescan sees the exact same vulnerability, but code was shifted to line 95!
	rawFinding2 := domain.RawFinding{
		ScannerFamily: "semgrep",
		Category:      domain.CategorySAST,
		RuleID:        "rules.security.sql_injection",
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  "./services/auth/db.go", // also tests path cleaning
				StartLine: 95,
				Snippet:   "  db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))  ", // whitespace padded
			},
		},
	}

	p1 := normalize.FingerprintParams{
		TenantID:      tenantID,
		AssetID:       assetID,
		ApplicationID: appID,
		Track:         "main",
		Family:        "semgrep",
		Category:      domain.CategorySAST,
		RuleID:        rawFinding1.RuleID,
		RawFinding:    rawFinding1,
	}

	p2 := normalize.FingerprintParams{
		TenantID:      tenantID,
		AssetID:       assetID,
		ApplicationID: appID,
		Track:         "main",
		Family:        "semgrep",
		Category:      domain.CategorySAST,
		RuleID:        rawFinding2.RuleID,
		RawFinding:    rawFinding2,
	}

	res1 := normalize.ComputeFingerprint(p1)
	res2 := normalize.ComputeFingerprint(p2)

	if res1.WeakFingerprint || res2.WeakFingerprint {
		t.Error("expected strong fingerprints when snippet is present")
	}

	if res1.FindingKey != res2.FindingKey {
		t.Fatalf("fingerprint unstable across line shift!\nKey 1 (line 42): %s\nKey 2 (line 95): %s", res1.FindingKey, res2.FindingKey)
	}
}

func TestSCAFingerprint(t *testing.T) {
	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()

	raw := domain.RawFinding{
		ScannerFamily: "trivy",
		Category:      domain.CategorySCA,
		RuleID:        "CVE-2023-44487",
		VulnIDs:       []string{"CVE-2023-44487"},
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:         "pkg:golang/net/http2@v0.14.0",
				PurlBase:     "pkg:golang/net/http2",
				ManifestPath: "go.sum",
			},
		},
	}

	p := normalize.FingerprintParams{
		TenantID:      tenantID,
		AssetID:       assetID,
		ApplicationID: appID,
		Track:         "main",
		Family:        "trivy",
		Category:      domain.CategorySCA,
		RuleID:        raw.RuleID,
		RawFinding:    raw,
	}

	res := normalize.ComputeFingerprint(p)
	if res.FindingKey == "" {
		t.Fatal("expected non-empty finding key")
	}
	if res.WeakFingerprint {
		t.Error("expected strong fingerprint for SCA with purl_base")
	}
}

func TestSecretFingerprint(t *testing.T) {
	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()

	raw := domain.RawFinding{
		ScannerFamily: "gitleaks",
		Category:      domain.CategorySecret,
		RuleID:        "aws-secret-access-key",
		SecretValue:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  "config/credentials.json",
				StartLine: 12,
			},
		},
	}

	p := normalize.FingerprintParams{
		TenantID:      tenantID,
		AssetID:       assetID,
		ApplicationID: appID,
		Track:         "prod",
		Family:        "gitleaks",
		Category:      domain.CategorySecret,
		RuleID:        raw.RuleID,
		RawFinding:    raw,
	}

	res := normalize.ComputeFingerprint(p)
	if res.FindingKey == "" {
		t.Fatal("expected non-empty finding key")
	}
	if res.WeakFingerprint {
		t.Error("expected strong fingerprint when secret value is hashed")
	}
}

func TestWeakFingerprintFallback(t *testing.T) {
	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()

	// SAST finding with no function and no snippet, only start_line
	raw := domain.RawFinding{
		ScannerFamily: "codeql",
		Category:      domain.CategorySAST,
		RuleID:        "js/xss",
		Location: domain.Location{
			Code: &domain.CodeLocation{
				FilePath:  "app/views.js",
				StartLine: 88,
			},
		},
	}

	p := normalize.FingerprintParams{
		TenantID:      tenantID,
		AssetID:       assetID,
		ApplicationID: appID,
		Track:         "main",
		Family:        "codeql",
		Category:      domain.CategorySAST,
		RuleID:        raw.RuleID,
		RawFinding:    raw,
	}

	res := normalize.ComputeFingerprint(p)
	if !res.WeakFingerprint {
		t.Error("expected weak_fingerprint=true when falling back to start_line")
	}
}

func TestContentHash(t *testing.T) {
	h1 := normalize.ComputeContentHash("SQL Injection", "Unsanitized user input", "HIGH", "CVSS:3.1/AV:N/AC:L", "", "src/db.go")
	h2 := normalize.ComputeContentHash("SQL Injection", "Unsanitized user input", "HIGH", "CVSS:3.1/AV:N/AC:L", "", "src/db.go")
	h3 := normalize.ComputeContentHash("SQL Injection Fixed", "Unsanitized user input", "HIGH", "CVSS:3.1/AV:N/AC:L", "1.2.3", "src/db.go")

	if h1 != h2 {
		t.Fatalf("expected identical content hashes for identical input, got %s and %s", h1, h2)
	}
	if h1 == h3 {
		t.Fatalf("expected different content hash when description/version changed")
	}
}
