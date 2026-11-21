package sbom

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/vex"
	"rampart/internal/wasmstore"
)

// ParseSBOMResultStream reads an SBOM or VEX document with the shipped module of its format and
// returns the complete Result, including VEX statements.
func ParseSBOMResultStream(ctx context.Context, format string, r io.Reader, limits Limits) (*Result, error) {
	norm := normalizeFormat(format)

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	code := findWasmBinary(format)
	var runErr error
	var res *Result
	if len(code) > 0 {
		res, runErr = run(ctx, code, bytes.NewReader(data), "sbom-"+norm, limits)
		if runErr == nil && (len(res.VEXStatements) > 0 || len(res.Components) > 0 || res.SBOM != nil) {
			return res, nil
		}
	} else {
		runErr = fmt.Errorf("%w: %q", ErrNoModule, format)
	}

	// Fallback for OpenVEX documents if module is missing or unable to parse 0.2 schema
	if norm == "openvex" || bytes.Contains(data, []byte("openvex.dev")) {
		if doc, parseErr := vex.Parse(data); parseErr == nil && doc != nil {
			vexRes := &Result{
				SBOM: &domain.SBOM{
					ID:        domain.NewID(),
					Format:    "openvex",
					CreatedAt: time.Now().UTC(),
				},
			}
			if limits.ExtractVEX {
				for _, st := range doc.Statements {
					if st.Problem != "" || len(st.Vulns) == 0 {
						continue
					}
					vulnID := st.Vulns[0]
					var aliases []string
					if len(st.Vulns) > 1 {
						aliases = st.Vulns[1:]
					}
					for _, p := range st.Purls {
						_, base, _ := normalize.CanonicalPURL(p)
						vexRes.VEXStatements = append(vexRes.VEXStatements, VEXStatement{
							VulnerabilityID: vulnID,
							Aliases:         aliases,
							Purl:            p,
							PurlBase:        base,
							Status:          st.State,
							Justification:   st.Justification,
							Impact:          st.Impact,
							Action:          st.Action,
							Timestamp:       st.At,
						})
					}
					if len(st.Purls) == 0 {
						vexRes.VEXStatements = append(vexRes.VEXStatements, VEXStatement{
							VulnerabilityID: vulnID,
							Aliases:         aliases,
							Status:          st.State,
							Justification:   st.Justification,
							Impact:          st.Impact,
							Action:          st.Action,
							Timestamp:       st.At,
						})
					}
				}
			}
			return vexRes, nil
		}
	}

	if runErr != nil {
		return nil, runErr
	}
	return res, nil
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
