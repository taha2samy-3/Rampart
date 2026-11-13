package integrations

import (
	"context"
	"io"
	"iter"

	"rampart/internal/domain"
	"rampart/internal/parsers/bandit"
	"rampart/internal/parsers/checkov"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/dependencycheck"
	"rampart/internal/parsers/dependencytrack"
	"rampart/internal/parsers/gitleaks"
	"rampart/internal/parsers/grype"
	"rampart/internal/parsers/kubebench"
	"rampart/internal/parsers/nuclei"
	"rampart/internal/parsers/openvex"
	"rampart/internal/parsers/prowler"
	"rampart/internal/parsers/sarif"
	"rampart/internal/parsers/semgrep"
	"rampart/internal/parsers/snyk"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
	"rampart/internal/parsers/trivy"
	"rampart/internal/parsers/trufflehog"
	"rampart/internal/parsers/zap"
)

type streamingParser interface {
	Name() string
	Detect(head []byte, filename string, contentType string) int
	Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error]
}

type parserAdapter struct {
	desc   Descriptor
	parser streamingParser
}

func (a *parserAdapter) Descriptor() Descriptor {
	return a.desc
}

func (a *parserAdapter) Detect(head []byte, filename string, contentType string) int {
	return a.parser.Detect(head, filename, contentType)
}

func (a *parserAdapter) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return a.parser.Parse(ctx, r, pc)
}

// DefaultRegistry creates an integration registry pre-loaded with all built-in Tier 1 & Tier 2 parsers.
func DefaultRegistry() *Registry {
	reg := NewRegistry()

	// 1. SARIF 2.1.0 (Tier 1)
	_ = reg.RegisterParser(&parserAdapter{
		desc: Descriptor{
			ID:           "builtin:sarif",
			Name:         "SARIF 2.1.0 Parser",
			Kind:         KindParser,
			Version:      "2.1.0",
			SupportLevel: SupportBuiltin,
			Description:  "Streaming SARIF parser with enrichers for Semgrep, Trivy, Gitleaks",
		},
		parser: sarif.NewParser(),
	})

	// 2. CycloneDX 1.4-1.7 JSON & XML (Tier 1)
	_ = reg.RegisterParser(&parserAdapter{
		desc: Descriptor{
			ID:           "builtin:cyclonedx",
			Name:         "CycloneDX Parser (JSON/XML)",
			Kind:         KindParser,
			Version:      "1.5.0",
			SupportLevel: SupportBuiltin,
			Description:  "CycloneDX 1.4-1.7 SBOM, VDR, and VEX parser for JSON and XML formats",
		},
		parser: cyclonedx.NewParser(),
	})

	// 3. SPDX 2.2/2.3 JSON & Tag-Value (Tier 2)
	_ = reg.RegisterParser(&parserAdapter{
		desc: Descriptor{
			ID:           "builtin:spdx",
			Name:         "SPDX Parser (JSON/Tag-Value)",
			Kind:         KindParser,
			Version:      "2.3.0",
			SupportLevel: SupportBuiltin,
			Description:  "SPDX 2.2 and 2.3 SBOM parser for JSON and Tag-Value formats",
		},
		parser: spdx.NewParser(),
	})

	// 4. OpenVEX (Tier 1)
	_ = reg.RegisterParser(&parserAdapter{
		desc: Descriptor{
			ID:           "builtin:openvex",
			Name:         "OpenVEX Parser",
			Kind:         KindParser,
			Version:      "0.2.0",
			SupportLevel: SupportBuiltin,
			Description:  "OpenVEX triage statements and exploitability assertions parser",
		},
		parser: openvex.NewParser(),
	})

	// 5. Anchore Syft JSON (Tier 2)
	_ = reg.RegisterParser(&parserAdapter{
		desc: Descriptor{
			ID:           "builtin:syft",
			Name:         "Syft Parser (JSON)",
			Kind:         KindParser,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Anchore Syft SBOM parser with artifact catalog and dependency relationships",
		},
		parser: syft.NewParser(),
	})

	// 6. The native JSON reports of the four most used scanners (docs/05, D15). Their SARIF output goes through the
	// SARIF parser; these read what the tools write by default, with more detail than SARIF carries.
	for _, p := range []struct {
		id, name, version, desc string
		parser                  streamingParser
	}{
		{"builtin:trivy", "Trivy Parser (JSON)", "2", "Trivy JSON (schema 2): package vulnerabilities, secrets, misconfigurations, licenses", trivy.NewParser()},
		{"builtin:grype", "Grype Parser (JSON)", "1", "Grype JSON: vulnerability matches with their related identifiers", grype.NewParser()},
		{"builtin:semgrep", "Semgrep Parser (JSON)", "1", "Semgrep JSON: code findings with CWE, location and code snippet hash", semgrep.NewParser()},
		{"builtin:trufflehog", "TruffleHog Parser (JSON lines)", "3", "TruffleHog JSON lines: secrets, with whether the credential is live; the secret is hashed and never stored", trufflehog.NewParser()},
		{"builtin:gitleaks", "Gitleaks Parser (JSON)", "1", "Gitleaks JSON: secrets found in a repository; the secret is hashed and never stored", gitleaks.NewParser()},
		{"builtin:dependencytrack", "Dependency-Track Parser (FPF/JSON)", "1.4", "Dependency-Track FPF export and direct API finding response parser with VEX and attribution", dependencytrack.NewParser()},
		{"builtin:checkov", "Checkov Parser (JSON)", "3", "Checkov IaC scanning report for Terraform, CloudFormation, K8s, Dockerfile", checkov.NewParser()},
		{"builtin:bandit", "Bandit Parser (JSON)", "1.7", "Bandit Python SAST vulnerability report", bandit.NewParser()},
		{"builtin:nuclei", "Nuclei Parser (JSONL)", "3", "Nuclei template-based vulnerability scan results", nuclei.NewParser()},
		{"builtin:zap", "OWASP ZAP Parser (JSON)", "2.14", "OWASP ZAP DAST web application security report", zap.NewParser()},
		{"builtin:dependencycheck", "OWASP Dependency-Check Parser (JSON)", "8.4", "OWASP Dependency-Check SCA vulnerability report", dependencycheck.NewParser()},
		{"builtin:snyk", "Snyk Parser (JSON)", "1", "Snyk open source and container vulnerability report", snyk.NewParser()},
		{"builtin:kubebench", "kube-bench Parser (JSON)", "0.6", "Aqua Security kube-bench CIS Kubernetes benchmark report", kubebench.NewParser()},
		{"builtin:prowler", "Prowler Parser (JSON)", "4", "Prowler AWS/Azure/GCP cloud security and compliance report", prowler.NewParser()},
	} {
		_ = reg.RegisterParser(&parserAdapter{
			desc:   Descriptor{ID: p.id, Name: p.name, Kind: KindParser, Version: p.version, SupportLevel: SupportBuiltin, Description: p.desc},
			parser: p.parser,
		})
	}

	// 7. Built-in Trackers
	_ = reg.RegisterTracker(NewJiraTrackerAdapter())
	_ = reg.RegisterTracker(NewGitHubTrackerAdapter())

	// 8. Built-in Notifiers
	_ = reg.RegisterNotifier(NewSlackNotifierAdapter())
	_ = reg.RegisterNotifier(NewTeamsNotifierAdapter())
	_ = reg.RegisterNotifier(NewEmailNotifierAdapter())
	_ = reg.RegisterNotifier(NewWebhookNotifierAdapter())

	// 9. Built-in Sources
	_ = reg.RegisterSource(NewDependencyTrackSourceAdapter())

	return reg
}
