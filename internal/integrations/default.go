package integrations

import (
	"context"
	"io"
	"iter"

	"rampart/internal/domain"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/openvex"
	"rampart/internal/parsers/sarif"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
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

	return reg
}
