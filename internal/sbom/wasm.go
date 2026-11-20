package sbom

import (
	"context"
	"fmt"
	"io"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/wasmstore"
)

// ParseSBOMStream reads an SBOM document (CycloneDX, SPDX, Syft, ...) with the shipped module of its format and
// returns the assets in it: the document, its components and its dependency edges. It never returns findings.
func ParseSBOMStream(ctx context.Context, format string, r io.Reader) (*domain.SBOM, []domain.SBOMComponent, []domain.DependencyEdge, error) {
	code := findWasmBinary(format)
	if len(code) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: %q", ErrNoModule, format)
	}
	res, err := run(ctx, code, r, "sbom-"+normalizeFormat(format), Limits{})
	if err != nil {
		return nil, nil, nil, err
	}
	return res.SBOM, res.Components, res.Edges, nil
}

func normalizeFormat(format string) string {
	format = strings.TrimPrefix(strings.ToLower(format), "cluster:")
	format = strings.TrimPrefix(format, "builtin:")
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
