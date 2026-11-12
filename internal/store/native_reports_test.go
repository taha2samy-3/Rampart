package store_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
)

// The native reports of Trivy, Grype, Semgrep and Gitleaks, uploaded without saying what they are, are detected,
// parsed, stored, scored and queryable, and no secret reaches the database.
func TestNativeReports_EndToEnd(t *testing.T) {
	h := newUploadHarness(t)
	h.formatHint = "" // nobody says what the report is: the processor detects it
	ctx := context.Background()

	reports := []struct {
		file    string
		context domain.UploadContext
		family  string
		want    int
	}{
		{"../parsers/trivy/testdata/image-0.50.json", domain.UploadContext{ImageRef: "registry.acme.example/shop/api:2.14.0", Branch: "main"}, "trivy", 5},
		{"../parsers/grype/testdata/image-0.74.json", domain.UploadContext{ImageRef: "registry.acme.example/shop/api:2.14.0", Branch: "main"}, "grype", 3},
		{"../parsers/semgrep/testdata/scan-1.45.json", domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}, "semgrep", 3},
		{"../parsers/gitleaks/testdata/repo-8.18.json", domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}, "gitleaks", 2},
		{"../parsers/trufflehog/testdata/scan-3.63.jsonl", domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}, "trufflehog", 3},
	}
	for _, r := range reports {
		report, err := os.ReadFile(r.file)
		if err != nil {
			t.Fatal(err)
		}
		run := h.waitRun(h.uploadAndComplete(report, r.context))
		if run.Status != domain.RunCompleted || run.Stats.Created != r.want {
			t.Fatalf("%s: run %s (%s), created %d, want %d", r.family, run.Status, run.Error, run.Stats.Created, r.want)
		}
		if got := h.page("scanner:"+r.family, "-score"); len(got) != r.want {
			t.Fatalf("scanner:%s returned %d findings, want %d", r.family, len(got), r.want)
		}
	}

	// Scored and stored like any other finding, and found by what they are.
	for q, want := range map[string]int{"category:secret": 7, "category:sca": 5, "category:iac": 1, "category:license": 1, "category:sast": 2} {
		if got := h.page(q, "-score"); len(got) != want {
			t.Fatalf("%s returned %d findings, want %d", q, len(got), want)
		}
	}
	for _, it := range h.page("", "-score") {
		if it.Finding.RiskScore == 0 || it.Finding.SLADue == nil && it.Finding.State.IsActive() {
			t.Fatalf("%s %s is not scored: score %d", it.Finding.RuleScannerFamily, it.Finding.RuleID, it.Finding.RiskScore)
		}
	}

	// Grype reported the GHSA advisory and the CVE related to it: the finding is under the CVE (D11).
	for _, it := range h.page("scanner:grype", "-score") {
		if it.Finding.RuleID == "GHSA-jfh8-c2jp-5v3q" && (it.Finding.VulnerabilityID == nil || *it.Finding.VulnerabilityID != "CVE-2021-44228") {
			t.Fatalf("the canonical id must be the CVE, got %v", it.Finding.VulnerabilityID)
		}
	}
	if got := h.page("cve:CVE-2021-44228", "-score"); len(got) != 1 {
		t.Fatalf("cve:CVE-2021-44228 returned %d findings", len(got))
	}
	// An image finding keeps its image as the asset (D10), a repository finding its repository.
	apps := map[domain.AssetType]int{}
	rows, err := h.pool.Query(ctx, `SELECT type, count(*) FROM asset WHERE tenant_id = $1 GROUP BY type`, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var typ string
		var n int
		_ = rows.Scan(&typ, &n)
		apps[domain.AssetType(typ)] = n
	}
	rows.Close()
	if apps[domain.AssetImage] != 1 || apps[domain.AssetRepository] != 1 {
		t.Fatalf("assets by type: %v, want one image and one repository", apps)
	}

	// A secret never reaches the database: not the AWS key Semgrep and Gitleaks saw, nor the API key.
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "7f3a9c1e5b2d48f6a0c9e1d3b5a7f9c2e4d6b8a0"} {
		var n int
		err := h.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM occurrence WHERE tenant_id = $1 AND (raw::text LIKE '%'||$2||'%' OR location::text LIKE '%'||$2||'%' OR normalized::text LIKE '%'||$2||'%'))
		  + (SELECT count(*) FROM finding WHERE tenant_id = $1 AND (location::text LIKE '%'||$2||'%' OR title LIKE '%'||$2||'%' OR description LIKE '%'||$2||'%'))`, h.tenant, secret).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("SECURITY VIOLATION: the secret %q is stored in %d places", secret[:6]+"...", n)
		}
	}
	for _, secret := range []string{"wJalrXUtnFEMI", "ghp_7f3a9c1e5b2d48f6", "xoxb-EXAMPLE-TOKEN"} {
		var n int
		_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM occurrence WHERE tenant_id = $1 AND raw::text LIKE '%'||$2||'%'`, h.tenant, secret).Scan(&n)
		if n != 0 {
			t.Fatalf("SECURITY VIOLATION: a TruffleHog credential (%s...) is stored", secret[:5])
		}
	}
	// A credential TruffleHog verified is live: it scores higher than the same kind of secret that was not, and the
	// difference is the SECRET_VERIFIED factor (docs/06, D42).
	var live, dead *domain.Finding
	for _, it := range h.page("scanner:trufflehog", "-score") {
		f := it.Finding // already a pointer
		switch f.RuleID {
		case "aws":
			live = f
		case "github":
			dead = f
		}
	}
	if live == nil || dead == nil || !live.SecretVerified || dead.SecretVerified {
		t.Fatalf("verification not stored: %+v %+v", live, dead)
	}
	if live.RiskScore < dead.RiskScore+250 {
		t.Fatalf("a live credential must outscore an unverified one by at least the SECRET_VERIFIED 250: %d vs %d", live.RiskScore, dead.RiskScore)
	}
	// When it is revoked, the next scan says unverified and the score falls; it is the same finding.
	report, _ := os.ReadFile("../parsers/trufflehog/testdata/scan-3.63.jsonl")
	revoked := strings.Replace(string(report), `"Verified":true`, `"Verified":false`, 1)
	run := h.waitRun(h.uploadAndComplete([]byte(revoked), domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}))
	if run.Status != domain.RunCompleted || run.Stats.Created != 0 || run.Stats.Updated != 1 {
		t.Fatalf("a changed verification is an update of the same finding: %s %+v", run.Status, run.Stats)
	}
	after, _, _ := h.store.GetFinding(ctx, h.tenant, live.ID)
	if after.SecretVerified || after.RiskScore >= live.RiskScore {
		t.Fatalf("after revocation: verified %v, score %d -> %d", after.SecretVerified, live.RiskScore, after.RiskScore)
	}
	// The records themselves are still there, redacted.
	var redacted int
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM occurrence WHERE tenant_id = $1 AND raw::text LIKE '%[redacted]%'`, h.tenant).Scan(&redacted)
	if redacted < 6 {
		t.Fatalf("%d redacted records, want the Gitleaks, TruffleHog and Semgrep ones", redacted)
	}
}
