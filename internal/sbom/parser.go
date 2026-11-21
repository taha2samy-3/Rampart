package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/normalize"
	"rampart/internal/vex"
	"rampart/internal/wasmstore"
)

var (
	ErrInvalidSBOMSpec = errors.New("sbom: invalid parser specification")
	ErrWasmExecution   = errors.New("sbom: wasm execution error")
)

// SBOMParserSpec defines the configuration of a generic declarative SBOM parser.
type SBOMParserSpec struct {
	Format      string `yaml:"format" json:"format"`
	Runtime     string `yaml:"runtime" json:"runtime"` // wasm, lua, native
	Description string `yaml:"description" json:"description"`
	Version     string `yaml:"version" json:"version"`
	Source      struct {
		OCI    string `yaml:"oci" json:"oci"`
		File   string `yaml:"file" json:"file"`
		Base64 string `yaml:"base64" json:"base64"`
	} `yaml:"source" json:"source"`
	Detect  domain.SBOMParserDetectSpec `yaml:"detect" json:"detect"`
	Options domain.SBOMParserOptions    `yaml:"options" json:"options"`
	Limits  struct {
		MaxMemoryMB int `yaml:"maxMemoryMB" json:"maxMemoryMB"`
	} `yaml:"limits" json:"limits"`
}

// WasmSBOMParser dynamically runs an SBOM parser in Wazero based on its CRD spec.
type WasmSBOMParser struct {
	name     string
	spec     SBOMParserSpec
	desc     integrations.Descriptor
	wasmCode []byte
}

// NewWasmSBOMParserFromSpec creates a generic dynamic SBOM parser from YAML/JSON manifest.
func NewWasmSBOMParserFromSpec(name string, raw []byte, wasmBinary []byte) (*WasmSBOMParser, error) {
	var manifest struct {
		Metadata struct {
			Name string `yaml:"name" json:"name"`
		} `yaml:"metadata" json:"metadata"`
		Spec SBOMParserSpec `yaml:"spec" json:"spec"`
	}

	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSBOMSpec, err)
	}

	spec := manifest.Spec
	if spec.Format == "" {
		spec.Format = manifest.Metadata.Name
	}
	if spec.Format == "" {
		spec.Format = name
	}

	code := wasmBinary
	store := wasmstore.Default()
	if len(code) == 0 && spec.Source.File != "" && !store.Strict() {
		fileCandidates := []string{
			spec.Source.File,
			filepath.Join("..", spec.Source.File),
			filepath.Join("..", "..", spec.Source.File),
			filepath.Join("..", "..", "..", spec.Source.File),
		}
		for _, cand := range fileCandidates {
			if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
				code = data
				break
			}
		}
	}
	if len(code) == 0 {
		cleanName := strings.TrimPrefix(name, "sbom-")
		data, _, err := store.Load(name, "sbom-"+cleanName, cleanName)
		switch {
		case err == nil:
			code = data
		case errors.Is(err, wasmstore.ErrNotFound):
			// left empty: Parse reports that no module was loaded
		default:
			return nil, fmt.Errorf("sbom: %w", err)
		}
	}

	desc := integrations.Descriptor{
		ID:           "cluster:sbom-" + spec.Format,
		Name:         spec.Format + " SBOM Parser",
		Kind:         integrations.KindParser,
		Category:     "sca",
		Version:      spec.Version,
		SupportLevel: integrations.SupportCluster,
		Description:  spec.Description,
	}

	return &WasmSBOMParser{
		name:     name,
		spec:     spec,
		desc:     desc,
		wasmCode: code,
	}, nil
}

func (p *WasmSBOMParser) Descriptor() integrations.Descriptor {
	return p.desc
}

// Detect checks if the document matches this parser's declarative rules dynamically.
func (p *WasmSBOMParser) Detect(head []byte, filename string, contentType string) int {
	return p.spec.Detect.Score(head, filename, contentType)
}

// Parse implements integrations.ParserContract. An SBOM reader fills the inventory through ParseSBOM, so Parse yields
// nothing. The findings of a reader whose option extractVulnerabilities is on come from ParseDocument, which reads
// the document once for both (the processor calls it).
func (p *WasmSBOMParser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {}
}

// ParseSBOM executes the sandboxed WASM module to extract the document metadata, the components and the
// dependency edges. It returns an error when the module fails or writes output it should not (host.go).
func (p *WasmSBOMParser) ParseSBOM(ctx context.Context, r io.Reader) (*domain.SBOM, []domain.SBOMComponent, []domain.DependencyEdge, error) {
	res, err := p.ParseSBOMResult(ctx, r)
	if err != nil {
		return nil, nil, nil, err
	}
	return res.SBOM, res.Components, res.Edges, nil
}

func (p *WasmSBOMParser) limits(extractVulns bool) Limits {
	return Limits{
		MaxMemoryMB:            p.spec.Limits.MaxMemoryMB,
		ExtractVulnerabilities: extractVulns,
		ExtractVEX:             p.spec.Options.ExtractVEX,
	}
}

// ExtractsVulnerabilities reports whether the spec turns the vulnerabilities a document states into findings.
func (p *WasmSBOMParser) ExtractsVulnerabilities() bool { return p.spec.Options.ExtractVulnerabilities }

// ExtractsVEX reports whether the spec turns VEX statements into decisions.
func (p *WasmSBOMParser) ExtractsVEX() bool { return p.spec.Options.ExtractVEX }

// ParseSBOMResult executes the sandboxed WASM module and returns the full Result including VEX statements.
func (p *WasmSBOMParser) ParseSBOMResult(ctx context.Context, r io.Reader) (*Result, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	res, runErr := run(ctx, p.wasmCode, bytes.NewReader(data), p.name, p.limits(p.spec.Options.ExtractVulnerabilities))
	if runErr == nil && len(res.VEXStatements) > 0 {
		return res, nil
	}
	// Fallback for OpenVEX documents
	if p.spec.Format == "openvex" || bytes.Contains(data, []byte("openvex.dev")) {
		if doc, parseErr := vex.Parse(data); parseErr == nil && doc != nil {
			vexRes := &Result{
				SBOM: &domain.SBOM{
					ID:        domain.NewID(),
					Format:    "openvex",
					CreatedAt: time.Now().UTC(),
				},
			}
			if p.spec.Options.ExtractVEX {
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

// ParseDocument reads the document once, with the module asked for the vulnerabilities the document states, and returns
// everything the run needs: the assets, and (through Findings) the findings. It is for a reader whose option
// extractVulnerabilities is on.
func (p *WasmSBOMParser) ParseDocument(ctx context.Context, r io.Reader) (*Document, error) {
	res, err := p.ParseSBOMResult(ctx, r)
	if err != nil {
		return nil, err
	}
	return &Document{SBOM: res.SBOM, Components: res.Components, Edges: res.Edges, res: res, format: p.spec.Format}, nil
}

// Document is an SBOM read together with the vulnerabilities it states.
type Document struct {
	SBOM       *domain.SBOM
	Components []domain.SBOMComponent
	Edges      []domain.DependencyEdge

	res    *Result
	format string
}

// Family is the scanner family of the findings of this document ("sbom-cyclonedx"): the scope a rescan closes, also
// when the new document states nothing.
func (d *Document) Family() string { return FamilyPrefix + normalizeFormat(d.format) }

// Findings are the vulnerabilities of the document as findings, one for each (vulnerability, component). A
// vulnerability that names a component the document does not contain is reported through pc.RecordError and left out,
// never attached to a guess: the run then ends completed-with-errors and closes nothing (D13).
func (d *Document) Findings(pc domain.ParseContext) []domain.RawFinding {
	return findingsOf(d.res, d.format, pc)
}

// VEXStatements returns the exploitability statements emitted during document parsing.
func (d *Document) VEXStatements() []VEXStatement {
	if d == nil || d.res == nil {
		return nil
	}
	return d.res.VEXStatements
}

// IsReader reports whether a parser reads an SBOM into assets instead of producing findings. It is the one rule
// the gateway, the processor and the CLI share: a parser is an SBOM reader when it is one, not when its name says so.
func IsReader(p integrations.ParserContract) bool {
	_, ok := p.(interface {
		ParseSBOM(ctx context.Context, r io.Reader) (*domain.SBOM, []domain.SBOMComponent, []domain.DependencyEdge, error)
	})
	return ok
}

// RequiredModules is the module this reader runs, under the names it is looked up as; none when the code was given with the reader.
func (p *WasmSBOMParser) RequiredModules() []string {
	if len(p.wasmCode) > 0 {
		return nil
	}
	clean := strings.TrimPrefix(p.name, "sbom-")
	return []string{p.name, "sbom-" + clean, clean}
}
