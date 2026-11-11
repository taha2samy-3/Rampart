package spdx

import (
	"bufio"
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

// Parser parses SPDX 2.2, 2.3, and 3.0 SBOM documents in JSON, JSON-LD, and Tag-Value formats (Feature A9, docs/05 §1).
type Parser struct{}

// NewParser creates a new SPDX parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the identifier of this parser.
func (p *Parser) Name() string {
	return "spdx"
}

// Detect checks if the document header indicates an SPDX format (JSON, JSON-LD, or Tag-Value).
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	score := 0
	lowerName := strings.ToLower(filename)
	if strings.Contains(lowerName, "spdx") || strings.HasSuffix(lowerName, ".spdx.json") || strings.HasSuffix(lowerName, ".spdx") || strings.HasSuffix(lowerName, ".spdx.jsonld") {
		score += 50
	}
	if strings.Contains(contentType, "spdx+json") || strings.Contains(contentType, "spdx") {
		score += 50
	}

	headStr := string(head)
	// SPDX 2.x JSON
	if strings.Contains(headStr, `"spdxVersion"`) {
		score += 60
	}
	// SPDX 3.x JSON-LD
	if (strings.Contains(headStr, "@graph") || strings.Contains(headStr, "@context")) && (strings.Contains(headStr, "spdx") || strings.Contains(headStr, "SoftwarePackage")) {
		score += 60
	}
	// SPDX Tag-Value
	if strings.Contains(headStr, "SPDXVersion:") && (strings.Contains(headStr, "SPDX-2.") || strings.Contains(headStr, "SPDX-3.")) {
		score += 60
	}

	if score > 100 {
		return 100
	}
	return score
}

type unifiedSPDXPackage struct {
	Name             string
	Version          string
	SPDXID           string
	Purl             string
	PurlBase         string
	CPE              string
	LicenseConcluded string
	Checksums        map[string]string
	RawJSON          []byte
}

// Parse extracts components and inventory items as RawFindings (License/SCA).
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		_, _, pkgs, _, err := parseSPDXAll(r)
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("spdx: parsing failed: %w", err))
			return
		}

		for _, pkg := range pkgs {
			if ctx.Err() != nil {
				return
			}

			loc := domain.Location{
				Package: &domain.PackageLocation{
					Purl:             pkg.Purl,
					PurlBase:         pkg.PurlBase,
					ComponentName:    pkg.Name,
					InstalledVersion: pkg.Version,
				},
			}

			ruleID := "spdx-pkg:" + pkg.Name
			if pkg.PurlBase != "" {
				ruleID = pkg.PurlBase
			}

			rf := domain.RawFinding{
				ScannerFamily: "spdx",
				ScannerName:   "spdx-sbom",
				Category:      domain.CategoryLicense,
				RuleID:        ruleID,
				Title:         normalize.NFC(fmt.Sprintf("Package: %s@%s", pkg.Name, pkg.Version)),
				Description:   normalize.NFC(fmt.Sprintf("Concluded License: %s", pkg.LicenseConcluded)),
				ToolSeverity:  "info",
				Severity:      domain.SeverityInfo,
				Location:      loc,
				RawPayload:    pkg.RawJSON,
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

// ParseSBOM extracts the full SBOM entity, component inventory, and dependency graph.
func (p *Parser) ParseSBOM(r io.Reader) (*domain.SBOM, []domain.SBOMComponent, *graph.DependencyGraph, error) {
	specVer, rootRef, pkgs, edges, err := parseSPDXAll(r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("spdx: failed to parse SBOM: %w", err)
	}

	var components []domain.SBOMComponent
	for _, pkg := range pkgs {
		var licenses []string
		if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" && pkg.LicenseConcluded != "NONE" {
			licenses = append(licenses, pkg.LicenseConcluded)
		}

		components = append(components, domain.SBOMComponent{
			Ref:      pkg.SPDXID,
			Purl:     pkg.Purl,
			PurlBase: pkg.PurlBase,
			Name:     pkg.Name,
			Version:  pkg.Version,
			Licenses: licenses,
			Hashes:   pkg.Checksums,
		})
	}

	depGraph := graph.NewDependencyGraph(components, edges, rootRef)
	depGraph.MarkDirectDependencies()

	for i, c := range depGraph.Components {
		components[i] = *c
	}

	sbom := &domain.SBOM{
		ID:             domain.NewID(),
		Format:         "spdx",
		SpecVersion:    specVer,
		RootComponent:  depGraph.RootRef,
		ComponentCount: len(components),
		Dependencies:   edges,
		CreatedAt:      time.Now().UTC(),
	}

	return sbom, components, depGraph, nil
}

func parseSPDXAll(r io.Reader) (string, string, []unifiedSPDXPackage, []domain.DependencyEdge, error) {
	br := bufio.NewReader(r)
	firstByte, err := peekNonWhitespace(br)
	if err != nil {
		return "", "", nil, nil, err
	}

	if firstByte == '{' {
		return parseSPDXJSONAll(br)
	}
	return parseSPDXTagValueAll(br)
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

func parseSPDXJSONAll(r io.Reader) (string, string, []unifiedSPDXPackage, []domain.DependencyEdge, error) {
	// First inspect if this is SPDX 3.0 JSON-LD or standard SPDX 2.x JSON
	var rawMap map[string]json.RawMessage
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&rawMap); err != nil {
		return "", "", nil, nil, fmt.Errorf("json decode error: %w", err)
	}

	// Check if SPDX 3.0 (@graph)
	if _, hasGraph := rawMap["@graph"]; hasGraph {
		return parseSPDX3JSONLD(rawMap)
	}

	// SPDX 2.x JSON
	var doc spdxDocument
	docBytes, err := json.Marshal(rawMap)
	if err != nil {
		return "", "", nil, nil, err
	}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return "", "", nil, nil, fmt.Errorf("spdx 2.x decode error: %w", err)
	}

	specVer := doc.SPDXVersion
	if specVer == "" {
		specVer = "SPDX-2.3"
	}

	var results []unifiedSPDXPackage
	for _, pkg := range doc.Packages {
		purl := ""
		cpe := ""
		for _, ref := range pkg.ExternalRefs {
			refType := strings.ToLower(ref.ReferenceType)
			if refType == "purl" {
				purl = ref.ReferenceLocator
			} else if strings.HasPrefix(refType, "cpe") {
				cpe = ref.ReferenceLocator
			}
		}

		_, purlBase, _ := normalize.CanonicalPURL(purl)

		hashes := make(map[string]string)
		for _, cs := range pkg.Checksums {
			hashes[strings.ToLower(cs.Algorithm)] = cs.ChecksumValue
		}

		rawBytes, _ := json.Marshal(pkg)

		results = append(results, unifiedSPDXPackage{
			Name:             pkg.Name,
			Version:          pkg.VersionInfo,
			SPDXID:           pkg.SPDXID,
			Purl:             purl,
			PurlBase:         purlBase,
			CPE:              cpe,
			LicenseConcluded: pkg.LicenseConcluded,
			Checksums:        hashes,
			RawJSON:          rawBytes,
		})
	}

	rootRef := ""
	var edges []domain.DependencyEdge

	for _, rel := range doc.Relationships {
		relType := strings.ToUpper(strings.TrimSpace(rel.RelationshipType))
		from := rel.SpdxElementId
		to := rel.RelatedSpdxElement

		switch relType {
		case "DESCRIBES":
			if strings.EqualFold(from, "SPDXRef-DOCUMENT") || rootRef == "" {
				rootRef = to
			}
		case "DESCRIBED_BY":
			if strings.EqualFold(to, "SPDXRef-DOCUMENT") || rootRef == "" {
				rootRef = from
			}
		case "DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK":
			edges = append(edges, domain.DependencyEdge{
				FromRef: from,
				ToRef:   to,
			})
		case "DEPENDENCY_OF", "CONTAINED_BY":
			edges = append(edges, domain.DependencyEdge{
				FromRef: to,
				ToRef:   from,
			})
		}
	}

	// Auto-fallback for rootRef: if not found by DESCRIBES, use document name or first package
	if rootRef == "" && len(results) > 0 {
		rootRef = results[0].SPDXID
	}

	return specVer, rootRef, results, edges, nil
}

// parseSPDX3JSONLD parses SPDX 3.0 specification documents with @graph JSON-LD structure.
func parseSPDX3JSONLD(rawMap map[string]json.RawMessage) (string, string, []unifiedSPDXPackage, []domain.DependencyEdge, error) {
	graphBytes, ok := rawMap["@graph"]
	if !ok {
		return "", "", nil, nil, fmt.Errorf("spdx 3.0 missing @graph")
	}

	var elements []map[string]any
	if err := json.Unmarshal(graphBytes, &elements); err != nil {
		return "", "", nil, nil, fmt.Errorf("spdx 3.0 unmarshal @graph error: %w", err)
	}

	specVer := "SPDX-3.0"
	var results []unifiedSPDXPackage
	var edges []domain.DependencyEdge
	rootRef := ""

	for _, elem := range elements {
		elemType, _ := elem["@type"].(string)
		spdxID, _ := elem["spdxId"].(string)
		if spdxID == "" {
			spdxID, _ = elem["@id"].(string)
		}

		switch elemType {
		case "SoftwarePackage", "Package":
			name, _ := elem["name"].(string)
			version, _ := elem["packageVersion"].(string)
			purl, _ := elem["packageUrl"].(string)
			_, purlBase, _ := normalize.CanonicalPURL(purl)

			rawBytes, _ := json.Marshal(elem)

			results = append(results, unifiedSPDXPackage{
				Name:      name,
				Version:   version,
				SPDXID:    spdxID,
				Purl:      purl,
				PurlBase:  purlBase,
				Checksums: make(map[string]string),
				RawJSON:   rawBytes,
			})
		case "Relationship":
			from, _ := elem["from"].(string)
			relType, _ := elem["relationshipType"].(string)

			var targets []string
			if toStr, ok := elem["to"].(string); ok {
				targets = append(targets, toStr)
			} else if toSlice, ok := elem["to"].([]any); ok {
				for _, item := range toSlice {
					if str, ok := item.(string); ok {
						targets = append(targets, str)
					}
				}
			}

			normRel := strings.ToLower(relType)
			for _, target := range targets {
				switch normRel {
				case "dependson", "contains", "hasdependency":
					edges = append(edges, domain.DependencyEdge{
						FromRef: from,
						ToRef:   target,
					})
				case "dependencyof", "containedby":
					edges = append(edges, domain.DependencyEdge{
						FromRef: target,
						ToRef:   from,
					})
				case "describes":
					rootRef = target
				}
			}
		}
	}

	if rootRef == "" && len(results) > 0 {
		rootRef = results[0].SPDXID
	}

	return specVer, rootRef, results, edges, nil
}

func parseSPDXTagValueAll(r io.Reader) (string, string, []unifiedSPDXPackage, []domain.DependencyEdge, error) {
	var results []unifiedSPDXPackage
	var edges []domain.DependencyEdge
	rootRef := ""
	specVer := "SPDX-2.3"

	scanner := bufio.NewScanner(r)

	var current *unifiedSPDXPackage

	flushCurrent := func() {
		if current != nil && current.Name != "" {
			rawBytes, _ := json.Marshal(current)
			current.RawJSON = rawBytes
			results = append(results, *current)
		}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		tag := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch tag {
		case "SPDXVersion":
			specVer = val
		case "PackageName":
			flushCurrent()
			current = &unifiedSPDXPackage{
				Name:      val,
				Checksums: make(map[string]string),
			}
		case "SPDXID":
			if current != nil {
				current.SPDXID = val
			}
		case "PackageVersion":
			if current != nil {
				current.Version = val
			}
		case "PackageLicenseConcluded":
			if current != nil {
				current.LicenseConcluded = val
			}
		case "PackageChecksum":
			if current != nil {
				csParts := strings.SplitN(val, ":", 2)
				if len(csParts) == 2 {
					alg := strings.ToLower(strings.TrimSpace(csParts[0]))
					hashVal := strings.TrimSpace(csParts[1])
					current.Checksums[alg] = hashVal
				}
			}
		case "ExternalRef":
			if current != nil {
				refFields := strings.Fields(val)
				if len(refFields) >= 3 {
					refType := strings.ToLower(refFields[1])
					refLocator := refFields[2]
					if refType == "purl" {
						current.Purl = refLocator
						_, purlBase, _ := normalize.CanonicalPURL(refLocator)
						current.PurlBase = purlBase
					} else if strings.HasPrefix(refType, "cpe") {
						current.CPE = refLocator
					}
				}
			}
		case "Relationship":
			// format: <source> <TYPE> <target>
			relFields := strings.Fields(val)
			if len(relFields) >= 3 {
				from := relFields[0]
				relType := strings.ToUpper(relFields[1])
				to := relFields[2]

				switch relType {
				case "DESCRIBES":
					if strings.EqualFold(from, "SPDXRef-DOCUMENT") || rootRef == "" {
						rootRef = to
					}
				case "DESCRIBED_BY":
					if strings.EqualFold(to, "SPDXRef-DOCUMENT") || rootRef == "" {
						rootRef = from
					}
				case "DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK":
					edges = append(edges, domain.DependencyEdge{
						FromRef: from,
						ToRef:   to,
					})
				case "DEPENDENCY_OF", "CONTAINED_BY":
					edges = append(edges, domain.DependencyEdge{
						FromRef: to,
						ToRef:   from,
					})
				}
			}
		}
	}

	flushCurrent()

	if err := scanner.Err(); err != nil {
		return "", "", nil, nil, fmt.Errorf("tag-value scan error: %w", err)
	}

	if rootRef == "" && len(results) > 0 {
		rootRef = results[0].SPDXID
	}

	return specVer, rootRef, results, edges, nil
}

type spdxDocument struct {
	SPDXVersion   string             `json:"spdxVersion"`
	Packages      []spdxPackage      `json:"packages"`
	Relationships []spdxRelationship `json:"relationships"`
}

type spdxPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	Checksums        []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
	ExternalRefs []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type spdxRelationship struct {
	SpdxElementId      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}
