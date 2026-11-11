package cyclonedx

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"

	"rampart/internal/domain"
	"rampart/internal/graph"
	"rampart/internal/normalize"
)

// Parser implements the CycloneDX 1.4–1.7 SBOM and VDR parser for both JSON and XML formats (docs/05 §1).
type Parser struct{}

// NewParser creates a new CycloneDX parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the identifier of this parser.
func (p *Parser) Name() string {
	return "cyclonedx"
}

// Detect checks if the document header indicates a CycloneDX JSON or XML document.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	score := 0
	lowerName := strings.ToLower(filename)
	if strings.Contains(lowerName, "cyclonedx") || strings.HasSuffix(lowerName, ".cdx.json") || strings.HasSuffix(lowerName, ".cdx.xml") {
		score += 50
	}
	if strings.Contains(contentType, "cyclonedx+json") || strings.Contains(contentType, "cyclonedx+xml") {
		score += 50
	}

	headStr := string(head)
	// CycloneDX JSON check
	if strings.Contains(headStr, `"bomFormat"`) && strings.Contains(headStr, `"CycloneDX"`) {
		score += 60
	}
	// CycloneDX XML check
	if strings.Contains(headStr, "<bom") && strings.Contains(headStr, "cyclonedx.org/schema/bom") {
		score += 60
	}
	if strings.Contains(headStr, `"specVersion"`) || strings.Contains(headStr, `specVersion="`) {
		score += 20
	}

	if score > 100 {
		return 100
	}
	return score
}

// Unified internal intermediate structures
type unifiedComponent struct {
	BOMRef   string
	Group    string
	Name     string
	Version  string
	Purl     string
	PurlBase string
	Type     string
	Scope    string
	Licenses []string
	Hashes   map[string]string
}

type unifiedVulnerability struct {
	ID          string
	Description string
	Detail      string
	Severity    string
	Score       float64
	CWEs        []int
	AffectRefs  []string
	VEXState    string
	VEXJust     string
	RawJSON     []byte
}

// Parse extracts vulnerabilities and component findings from CycloneDX VDR/VEX documents.
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		_, _, comps, _, vulns, err := parseCycloneDXAll(r)
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("cyclonedx: parse failed: %w", err))
			return
		}

		// Index components by bom-ref and purl
		compMap := make(map[string]unifiedComponent)
		for _, comp := range comps {
			if comp.BOMRef != "" {
				compMap[comp.BOMRef] = comp
			}
			if comp.Purl != "" {
				compMap[comp.Purl] = comp
			}
		}

		// Extract VDR / VEX vulnerabilities
		for _, vuln := range vulns {
			if ctx.Err() != nil {
				return
			}

			// Map affected components
			for _, affectRef := range vuln.AffectRefs {
				comp, hasComp := compMap[affectRef]
				raw := mapUnifiedVulnToRawFinding(vuln, comp, hasComp)

				if !yield(raw, nil) {
					return
				}
			}

			// If no specific component is linked, still yield the vulnerability
			if len(vuln.AffectRefs) == 0 {
				raw := mapUnifiedVulnToRawFinding(vuln, unifiedComponent{}, false)
				if !yield(raw, nil) {
					return
				}
			}
		}
	}
}

// ParseComponents extracts pure SBOM components with dependency classification for the inventory table.
func (p *Parser) ParseComponents(r io.Reader) ([]domain.SBOMComponent, error) {
	_, comps, _, err := p.ParseSBOM(r)
	return comps, err
}

// ParseSBOM extracts the full SBOM entity, component inventory, and dependency graph.
func (p *Parser) ParseSBOM(r io.Reader) (*domain.SBOM, []domain.SBOMComponent, *graph.DependencyGraph, error) {
	specVer, rootRef, comps, edges, _, err := parseCycloneDXAll(r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cyclonedx: decoding SBOM failed: %w", err)
	}

	var components []domain.SBOMComponent
	for _, comp := range comps {
		components = append(components, domain.SBOMComponent{
			Ref:      comp.BOMRef,
			Purl:     comp.Purl,
			PurlBase: comp.PurlBase,
			Name:     comp.Name,
			Version:  comp.Version,
			Scope:    comp.Scope,
			Licenses: comp.Licenses,
			Hashes:   comp.Hashes,
		})
	}

	depGraph := graph.NewDependencyGraph(components, edges, rootRef)
	depGraph.MarkDirectDependencies()

	// Update components slice with resolved Direct flags from the graph
	for i, c := range depGraph.Components {
		components[i] = *c
	}

	sbom := &domain.SBOM{
		ID:             domain.NewID(),
		Format:         "cyclonedx",
		SpecVersion:    specVer,
		RootComponent:  depGraph.RootRef,
		ComponentCount: len(components),
		Dependencies:   edges,
		CreatedAt:      time.Now().UTC(),
	}

	return sbom, components, depGraph, nil
}

func parseCycloneDXAll(r io.Reader) (string, string, []unifiedComponent, []domain.DependencyEdge, []unifiedVulnerability, error) {
	br := bufio.NewReader(r)
	firstByte, err := peekNonWhitespace(br)
	if err != nil {
		return "", "", nil, nil, nil, err
	}

	if firstByte == '<' {
		return parseCycloneDXXML(br)
	}
	return parseCycloneDXJSON(br)
}

func peekNonWhitespace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			_ = br.UnreadByte()
			return b, nil
		}
	}
}

func parseCycloneDXJSON(r io.Reader) (string, string, []unifiedComponent, []domain.DependencyEdge, []unifiedVulnerability, error) {
	var doc cdxJSONDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return "", "", nil, nil, nil, fmt.Errorf("json decode error: %w", err)
	}

	specVer := doc.SpecVersion
	if specVer == "" {
		specVer = "1.5"
	}

	rootRef := ""
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		if doc.Metadata.Component.BOMRef != "" {
			rootRef = doc.Metadata.Component.BOMRef
		} else if doc.Metadata.Component.Purl != "" {
			rootRef = doc.Metadata.Component.Purl
		} else if doc.Metadata.Component.Name != "" {
			rootRef = doc.Metadata.Component.Name + "@" + doc.Metadata.Component.Version
		}
	}

	var comps []unifiedComponent
	for _, c := range doc.Components {
		purl := c.Purl
		_, purlBase, _ := normalize.CanonicalPURL(purl)

		var licenses []string
		for _, lic := range c.Licenses {
			if lic.License.ID != "" {
				licenses = append(licenses, lic.License.ID)
			} else if lic.License.Name != "" {
				licenses = append(licenses, lic.License.Name)
			} else if lic.Expression != "" {
				licenses = append(licenses, lic.Expression)
			}
		}

		hashes := make(map[string]string)
		for _, h := range c.Hashes {
			if h.Alg != "" && h.Content != "" {
				hashes[strings.ToLower(h.Alg)] = h.Content
			}
		}

		comps = append(comps, unifiedComponent{
			BOMRef:   c.BOMRef,
			Group:    c.Group,
			Name:     c.Name,
			Version:  c.Version,
			Purl:     purl,
			PurlBase: purlBase,
			Type:     c.Type,
			Scope:    c.Scope,
			Licenses: licenses,
			Hashes:   hashes,
		})
	}

	var edges []domain.DependencyEdge
	for _, d := range doc.Dependencies {
		for _, dep := range d.DependsOn {
			edges = append(edges, domain.DependencyEdge{
				FromRef: d.Ref,
				ToRef:   dep,
			})
		}
	}

	var vulns []unifiedVulnerability
	for _, v := range doc.Vulnerabilities {
		sev := "medium"
		score := 0.0
		if len(v.Ratings) > 0 {
			sev = v.Ratings[0].Severity
			score = v.Ratings[0].Score
		}

		var refs []string
		for _, a := range v.Affects {
			if a.Ref != "" {
				refs = append(refs, a.Ref)
			}
		}

		vexState := ""
		vexJust := ""
		if v.Analysis != nil {
			vexState = v.Analysis.State
			vexJust = v.Analysis.Justification
		}

		rawBytes, _ := json.Marshal(v)

		vulns = append(vulns, unifiedVulnerability{
			ID:          v.ID,
			Description: v.Description,
			Detail:      v.Detail,
			Severity:    sev,
			Score:       score,
			CWEs:        v.CWEs,
			AffectRefs:  refs,
			VEXState:    vexState,
			VEXJust:     vexJust,
			RawJSON:     rawBytes,
		})
	}

	return specVer, rootRef, comps, edges, vulns, nil
}

func parseCycloneDXXML(r io.Reader) (string, string, []unifiedComponent, []domain.DependencyEdge, []unifiedVulnerability, error) {
	var doc cdxXMLDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return "", "", nil, nil, nil, fmt.Errorf("xml decode error: %w", err)
	}

	specVer := doc.SpecVersion
	if specVer == "" {
		specVer = "1.5"
	}

	rootRef := ""
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		if doc.Metadata.Component.BOMRef != "" {
			rootRef = doc.Metadata.Component.BOMRef
		} else if doc.Metadata.Component.Purl != "" {
			rootRef = doc.Metadata.Component.Purl
		} else if doc.Metadata.Component.Name != "" {
			rootRef = doc.Metadata.Component.Name + "@" + doc.Metadata.Component.Version
		}
	}

	var comps []unifiedComponent
	for _, c := range doc.Components {
		purl := c.Purl
		_, purlBase, _ := normalize.CanonicalPURL(purl)

		var licenses []string
		for _, lic := range c.Licenses {
			if lic.ID != "" {
				licenses = append(licenses, lic.ID)
			} else if lic.Name != "" {
				licenses = append(licenses, lic.Name)
			}
		}

		hashes := make(map[string]string)
		for _, h := range c.Hashes {
			if h.Alg != "" && h.Value != "" {
				hashes[strings.ToLower(h.Alg)] = strings.TrimSpace(h.Value)
			}
		}

		comps = append(comps, unifiedComponent{
			BOMRef:   c.BOMRef,
			Group:    c.Group,
			Name:     c.Name,
			Version:  c.Version,
			Purl:     purl,
			PurlBase: purlBase,
			Type:     c.Type,
			Scope:    c.Scope,
			Licenses: licenses,
			Hashes:   hashes,
		})
	}

	var edges []domain.DependencyEdge
	for _, d := range doc.Dependencies {
		for _, dep := range d.DependsOn {
			if dep.Ref != "" {
				edges = append(edges, domain.DependencyEdge{
					FromRef: d.Ref,
					ToRef:   dep.Ref,
				})
			}
		}
	}

	var vulns []unifiedVulnerability
	for _, v := range doc.Vulnerabilities {
		sev := "medium"
		score := 0.0
		if len(v.Ratings) > 0 {
			sev = v.Ratings[0].Severity
			score = v.Ratings[0].Score
		}

		var refs []string
		for _, a := range v.Affects {
			if a.Ref != "" {
				refs = append(refs, a.Ref)
			}
		}

		rawBytes, _ := json.Marshal(v)

		vulns = append(vulns, unifiedVulnerability{
			ID:          v.ID,
			Description: v.Description,
			Detail:      v.Detail,
			Severity:    sev,
			Score:       score,
			CWEs:        v.CWEs,
			AffectRefs:  refs,
			VEXState:    v.Analysis.State,
			VEXJust:     v.Analysis.Justification,
			RawJSON:     rawBytes,
		})
	}

	return specVer, rootRef, comps, edges, vulns, nil
}

func mapUnifiedVulnToRawFinding(v unifiedVulnerability, c unifiedComponent, hasComp bool) domain.RawFinding {
	title := v.Description
	if title == "" {
		title = v.ID
	}

	sev := domain.ParseSeverity(v.Severity)

	var loc domain.Location
	if hasComp {
		loc.Package = &domain.PackageLocation{
			Purl:             c.Purl,
			PurlBase:         c.PurlBase,
			ComponentName:    c.Name,
			InstalledVersion: c.Version,
		}
	}

	var vexStatement *domain.VEXStatement
	if v.VEXState != "" {
		vexStatement = &domain.VEXStatement{
			StatementID:   domain.NewID(),
			State:         domain.FindingState(v.VEXState),
			Justification: v.VEXJust,
		}
	}

	return domain.RawFinding{
		ScannerFamily: "cyclonedx",
		ScannerName:   "cyclonedx-vdr",
		Category:      domain.CategorySCA,
		RuleID:        v.ID,
		Title:         normalize.NFC(title),
		Description:   normalize.NFC(v.Detail),
		ToolSeverity:  v.Severity,
		Severity:      sev,
		Location:      loc,
		CWEs:          v.CWEs,
		VulnIDs:       []string{v.ID},
		VEX:           vexStatement,
		RawPayload:    v.RawJSON,
	}
}

// JSON data structures
type cdxJSONDocument struct {
	BOMFormat       string                 `json:"bomFormat"`
	SpecVersion     string                 `json:"specVersion"`
	SerialNumber    string                 `json:"serialNumber"`
	Version         int                    `json:"version"`
	Metadata        *cdxJSONMetadata       `json:"metadata"`
	Components      []cdxJSONComponent     `json:"components"`
	Dependencies    []cdxJSONDependency    `json:"dependencies"`
	Vulnerabilities []cdxJSONVulnerability `json:"vulnerabilities"`
}

type cdxJSONMetadata struct {
	Component *cdxJSONComponent `json:"component"`
}

type cdxJSONDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxJSONComponent struct {
	BOMRef   string           `json:"bom-ref"`
	Group    string           `json:"group"`
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	Purl     string           `json:"purl"`
	Type     string           `json:"type"`
	Scope    string           `json:"scope"`
	Licenses []cdxJSONLicense `json:"licenses"`
	Hashes   []cdxJSONHash    `json:"hashes"`
}

type cdxJSONLicense struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxJSONHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxJSONVulnerability struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Ratings     []struct {
		Severity string  `json:"severity"`
		Score    float64 `json:"score"`
		Method   string  `json:"method"`
	} `json:"ratings"`
	CWEs    []int `json:"cwes"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
	Analysis *struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
	} `json:"analysis"`
}

// XML data structures
type cdxXMLDocument struct {
	XMLName         xml.Name              `xml:"bom"`
	SpecVersion     string                `xml:"version,attr"`
	SerialNumber    string                `xml:"serialNumber,attr"`
	Metadata        *cdxXMLMetadata       `xml:"metadata"`
	Components      []cdxXMLComponent     `xml:"components>component"`
	Dependencies    []cdxXMLDependency    `xml:"dependencies>dependency"`
	Vulnerabilities []cdxXMLVulnerability `xml:"vulnerabilities>vulnerability"`
}

type cdxXMLMetadata struct {
	Component *cdxXMLComponent `xml:"component"`
}

type cdxXMLDependency struct {
	Ref       string                `xml:"ref,attr"`
	DependsOn []cdxXMLDependencyRef `xml:"dependency"`
}

type cdxXMLDependencyRef struct {
	Ref string `xml:"ref,attr"`
}

type cdxXMLComponent struct {
	BOMRef   string          `xml:"bom-ref,attr"`
	Type     string          `xml:"type,attr"`
	Group    string          `xml:"group"`
	Name     string          `xml:"name"`
	Version  string          `xml:"version"`
	Purl     string          `xml:"purl"`
	Scope    string          `xml:"scope"`
	Licenses []cdxXMLLicense `xml:"licenses>license"`
	Hashes   []cdxXMLHash    `xml:"hashes>hash"`
}

type cdxXMLLicense struct {
	ID   string `xml:"id"`
	Name string `xml:"name"`
}

type cdxXMLHash struct {
	Alg   string `xml:"alg,attr"`
	Value string `xml:",chardata"`
}

type cdxXMLVulnerability struct {
	BOMRef      string `xml:"bom-ref,attr"`
	ID          string `xml:"id"`
	Description string `xml:"description"`
	Detail      string `xml:"detail"`
	Ratings     []struct {
		Severity string  `xml:"severity"`
		Score    float64 `xml:"score"`
		Method   string  `xml:"method"`
	} `xml:"ratings>rating"`
	CWEs    []int `xml:"cwes>cwe"`
	Affects []struct {
		Ref string `xml:"ref"`
	} `xml:"affects>target"`
	Analysis struct {
		State         string `xml:"state"`
		Justification string `xml:"justification"`
		Response      string `xml:"response"`
		Detail        string `xml:"detail"`
	} `xml:"analysis"`
}
