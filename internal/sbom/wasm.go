package sbom

import (
	"context"
	"fmt"
	"io"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/wasmstore"
)

// ParseSBOMResultStream reads an SBOM or VEX document with the shipped WASM module of its format and
// returns the complete Result, including VEX statements.
func ParseSBOMResultStream(ctx context.Context, format string, r io.Reader, limits Limits) (*Result, error) {
	norm := normalizeFormat(format)
	code := findWasmBinary(format)
	if len(code) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoModule, format)
	}
	return run(ctx, code, r, "sbom-"+norm, limits)
}

// ParseSBOMStream reads an SBOM document (CycloneDX, SPDX, Syft, OpenVEX, ...) with the shipped module of its format and
// returns the assets in it: the document, its components and its dependency edges. It never returns findings.
func ParseSBOMStream(ctx context.Context, format string, r io.Reader) (*domain.SBOM, []domain.SBOMComponent, []domain.DependencyEdge, error) {
	norm := normalizeFormat(format)
	var limits Limits
	if norm == "openvex" {
		limits.ExtractVEX = true
	}
	res, err := ParseSBOMResultStream(ctx, format, r, limits)
	if err != nil {
		return nil, nil, nil, err
	}
	return res.SBOM, res.Components, res.Edges, nil
}

func normalizeFormat(format string) string {
	format = strings.TrimPrefix(strings.ToLower(format), "cluster:")
	return strings.TrimPrefix(format, "sbom-")
}

func findWasmBinary(format string) []byte {
	format = normalizeFormat(format)
	code, _, err := wasmstore.Default().Load("sbom-"+format, format)
	if err != nil {
		return nil
	}
	return code
}
