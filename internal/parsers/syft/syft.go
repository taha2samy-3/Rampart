package syft

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"

	"rampart/internal/domain"
	"rampart/internal/graph"
	"rampart/internal/normalize"
)

// Parser parses Anchore Syft JSON SBOM documents (Feature A9, docs/05 §1).
type Parser struct{}

// NewParser creates a new Syft parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the identifier of this parser.
func (p *Parser) Name() string {
	return "syft"
}

// Detect checks if the document header indicates an Anchore Syft JSON document.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	score := 0
	lowerName := strings.ToLower(filename)
	if strings.Contains(lowerName, "syft") || strings.HasSuffix(lowerName, ".syft.json") {
		score += 50
	}
	if strings.Contains(contentType, "syft+json") {
		score += 50
	}

	headStr := string(head)
	if strings.Contains(headStr, `"artifacts"`) && strings.Contains(headStr, `"artifactRelationships"`) {
		score += 60
	}
	if strings.Contains(headStr, `"syft"`) {
		score += 30
	}

	if score > 100 {
		return 100
	}
	return score
}

type syftDocument struct {
	Artifacts             []syftArtifact     `json:"artifacts"`
	ArtifactRelationships []syftRelationship `json:"artifactRelationships"`
	Source                *syftSource        `json:"source,omitempty"`
	Descriptor            *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor,omitempty"`
	Schema *struct {
		Version string `json:"version"`
		URL     string `json:"url"`
	} `json:"schema,omitempty"`
}

type syftArtifact struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Purl     string `json:"purl"`
	Licenses []struct {
		Value          string `json:"value"`
		SPDXExpression string `json:"spdxExpression"`
	} `json:"licenses"`
	CPEs []struct {
		CPE string `json:"cpe"`
	} `json:"cpes"`
}

type syftRelationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

type syftSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Target  string `json:"target"`
}

// Parse extracts components and inventory items as RawFindings (License/SCA).
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		_, comps, _, err := p.ParseSBOM(r)
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("syft: parsing failed: %w", err))
			return
		}

		for _, comp := range comps {
			if ctx.Err() != nil {
				return
			}

			loc := domain.Location{
				Package: &domain.PackageLocation{
					Purl:             comp.Purl,
					PurlBase:         comp.PurlBase,
					ComponentName:    comp.Name,
					InstalledVersion: comp.Version,
				},
			}

			ruleID := "syft-pkg:" + comp.Name
			if comp.PurlBase != "" {
				ruleID = comp.PurlBase
			}

			title := fmt.Sprintf("Package: %s@%s", comp.Name, comp.Version)
			desc := fmt.Sprintf("Extracted package %s with %d license(s)", comp.Name, len(comp.Licenses))

			rf := domain.RawFinding{
				ScannerFamily: "syft",
				ScannerName:   "syft-sbom",
				Category:      domain.CategoryLicense,
				RuleID:        ruleID,
				Title:         normalize.NFC(title),
				Description:   normalize.NFC(desc),
				ToolSeverity:  "info",
				Severity:      domain.SeverityInfo,
				Location:      loc,
			}

			if !yield(rf, nil) {
				return
			}
		}
	}
}

// ParseComponents extracts pure SBOM components for the inventory table.
func (p *Parser) ParseComponents(r io.Reader) ([]domain.SBOMComponent, error) {
	_, comps, _, err := p.ParseSBOM(r)
	return comps, err
}

// ParseSBOM extracts the full SBOM entity, component inventory, and dependency graph from Syft JSON.
func (p *Parser) ParseSBOM(r io.Reader) (*domain.SBOM, []domain.SBOMComponent, *graph.DependencyGraph, error) {
	var doc syftDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, nil, nil, fmt.Errorf("syft: json decode error: %w", err)
	}

	specVer := "1.0"
	if doc.Schema != nil && doc.Schema.Version != "" {
		specVer = doc.Schema.Version
	} else if doc.Descriptor != nil && doc.Descriptor.Version != "" {
		specVer = doc.Descriptor.Version
	}

	// Index artifacts by ID for relationship mapping
	artifactMap := make(map[string]syftArtifact)
	var components []domain.SBOMComponent

	for _, art := range doc.Artifacts {
		artifactMap[art.ID] = art

		purl := art.Purl
		_, purlBase, _ := normalize.CanonicalPURL(purl)

		var licenses []string
		for _, lic := range art.Licenses {
			if lic.Value != "" {
				licenses = append(licenses, lic.Value)
			} else if lic.SPDXExpression != "" {
				licenses = append(licenses, lic.SPDXExpression)
			}
		}

		ref := art.ID
		if art.Purl != "" {
			ref = art.Purl
		}

		components = append(components, domain.SBOMComponent{
			Ref:      ref,
			Purl:     purl,
			PurlBase: purlBase,
			Name:     art.Name,
			Version:  art.Version,
			Licenses: licenses,
		})
	}

	// Map relationships into edges
	var edges []domain.DependencyEdge
	for _, rel := range doc.ArtifactRelationships {
		parentArt, parentOk := artifactMap[rel.Parent]
		childArt, childOk := artifactMap[rel.Child]

		parentRef := rel.Parent
		if parentOk && parentArt.Purl != "" {
			parentRef = parentArt.Purl
		}
		childRef := rel.Child
		if childOk && childArt.Purl != "" {
			childRef = childArt.Purl
		}

		normType := strings.ToLower(rel.Type)
		switch normType {
		case "depends-on", "contains":
			edges = append(edges, domain.DependencyEdge{
				FromRef: parentRef,
				ToRef:   childRef,
			})
		case "dependency-of":
			edges = append(edges, domain.DependencyEdge{
				FromRef: childRef,
				ToRef:   parentRef,
			})
		}
	}

	rootRef := ""
	if doc.Source != nil && doc.Source.Name != "" {
		rootRef = doc.Source.Name
		if doc.Source.Version != "" {
			rootRef += "@" + doc.Source.Version
		}
	}

	depGraph := graph.NewDependencyGraph(components, edges, rootRef)
	depGraph.MarkDirectDependencies()

	for i, c := range depGraph.Components {
		components[i] = *c
	}

	sbom := &domain.SBOM{
		ID:             domain.NewID(),
		Format:         "syft",
		SpecVersion:    specVer,
		RootComponent:  depGraph.RootRef,
		ComponentCount: len(components),
		Dependencies:   edges,
		CreatedAt:      time.Now().UTC(),
	}

	return sbom, components, depGraph, nil
}
