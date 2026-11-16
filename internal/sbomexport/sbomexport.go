// Package sbomexport writes the SBOMs Rampart holds as standard documents (doc 11 `GET /applications/{id}/sbom`,
// docs/16 D95): CycloneDX 1.6 JSON and SPDX 2.3 JSON, for one asset or merged for an application.
package sbomexport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// Part is the latest SBOM of one asset.
type Part struct {
	AssetName  string
	SBOM       *domain.SBOM
	Components []domain.SBOMComponent
}

// Subject names what the document describes: an asset, or an application with several assets.
type Subject struct {
	Name    string
	Version string
}

type merged struct {
	key   string
	comp  domain.SBOMComponent
	from  []string // the assets it was found in
	edges map[string]bool
}

// componentKey identifies a component across assets: its purl, else name and version.
func componentKey(c domain.SBOMComponent) string {
	if c.Purl != "" {
		return c.Purl
	}
	return "name:" + c.Name + "@" + c.Version
}

// merge unions the parts. A component found in several assets appears once, with every asset it came from as a
// property; dependency edges are kept between the merged components.
func merge(parts []Part) []*merged {
	byKey := map[string]*merged{}
	var order []string
	for _, p := range parts {
		refKey := map[string]string{}
		for _, c := range p.Components {
			k := componentKey(c)
			if c.Ref != "" {
				refKey[c.Ref] = k
			}
			refKey[c.Purl] = k
			m, ok := byKey[k]
			if !ok {
				m = &merged{key: k, comp: c, edges: map[string]bool{}}
				byKey[k] = m
				order = append(order, k)
			}
			if !contains(m.from, p.AssetName) {
				m.from = append(m.from, p.AssetName)
			}
		}
		if p.SBOM == nil {
			continue
		}
		for _, e := range p.SBOM.Dependencies {
			from, to := refKey[e.FromRef], refKey[e.ToRef]
			if from != "" && to != "" && from != to {
				byKey[from].edges[to] = true
			}
		}
	}
	sort.Strings(order)
	out := make([]*merged, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// bomRef is a stable, document-local reference for a merged component.
func bomRef(key string) string {
	h := sha256.Sum256([]byte(key))
	return "c-" + hex.EncodeToString(h[:8])
}

var hashAlgCDX = map[string]string{"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5",
	"SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512", "MD5": "MD5"}

// CycloneDX returns a CycloneDX 1.6 JSON document.
func CycloneDX(subject Subject, parts []Part, now time.Time) map[string]any {
	comps := merge(parts)
	components := make([]map[string]any, 0, len(comps))
	deps := make([]map[string]any, 0, len(comps))
	for _, m := range comps {
		c := m.comp
		e := map[string]any{"type": "library", "bom-ref": bomRef(m.key), "name": c.Name}
		if c.Version != "" {
			e["version"] = c.Version
		}
		if c.Purl != "" {
			e["purl"] = c.Purl
		}
		if c.Scope != "" {
			e["scope"] = c.Scope
		}
		if len(c.Licenses) > 0 {
			ls := make([]map[string]any, 0, len(c.Licenses))
			for _, l := range c.Licenses {
				if strings.ContainsAny(l, " ()") {
					ls = append(ls, map[string]any{"expression": l})
				} else {
					ls = append(ls, map[string]any{"license": map[string]any{"id": l}})
				}
			}
			e["licenses"] = ls
		}
		var hashes []map[string]any
		for alg, v := range c.Hashes {
			if a, ok := hashAlgCDX[alg]; ok {
				hashes = append(hashes, map[string]any{"alg": a, "content": v})
			}
		}
		if len(hashes) > 0 {
			sort.Slice(hashes, func(i, j int) bool { return hashes[i]["alg"].(string) < hashes[j]["alg"].(string) })
			e["hashes"] = hashes
		}
		props := []map[string]any{}
		for _, a := range m.from {
			props = append(props, map[string]any{"name": "rampart:asset", "value": a})
		}
		e["properties"] = props
		components = append(components, e)
		var on []string
		for k := range m.edges {
			on = append(on, bomRef(k))
		}
		sort.Strings(on)
		deps = append(deps, map[string]any{"ref": bomRef(m.key), "dependsOn": on})
	}
	meta := map[string]any{"timestamp": now.UTC().Format(time.RFC3339),
		"tools":     map[string]any{"components": []map[string]any{{"type": "application", "name": "rampart"}}},
		"component": map[string]any{"type": "application", "bom-ref": "subject", "name": subject.Name}}
	if subject.Version != "" {
		meta["component"].(map[string]any)["version"] = subject.Version
	}
	return map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": "urn:uuid:" + uuid.NewString(),
		"metadata":     meta, "components": components, "dependencies": deps,
	}
}

var spdxIDUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]`)

// SPDX returns an SPDX 2.3 JSON document. Licenses are written as declared; what Rampart did not record is
// NOASSERTION, never a guess.
func SPDX(subject Subject, parts []Part, now time.Time, namespaceBase string) map[string]any {
	comps := merge(parts)
	pkgs := []map[string]any{{"SPDXID": "SPDXRef-Subject", "name": subject.Name, "downloadLocation": "NOASSERTION",
		"filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"}}
	rels := []map[string]any{{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Subject"}}
	id := func(key string) string { return "SPDXRef-" + spdxIDUnsafe.ReplaceAllString(bomRef(key), "-") }
	hasParent := map[string]bool{}
	for _, m := range comps {
		for k := range m.edges {
			hasParent[k] = true
		}
	}
	for _, m := range comps {
		c := m.comp
		lic := "NOASSERTION"
		if len(c.Licenses) == 1 {
			lic = c.Licenses[0]
		} else if len(c.Licenses) > 1 {
			lic = "(" + strings.Join(c.Licenses, " AND ") + ")"
		}
		p := map[string]any{"SPDXID": id(m.key), "name": c.Name, "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
			"licenseConcluded": "NOASSERTION", "licenseDeclared": lic, "copyrightText": "NOASSERTION",
			"comment": "Found in: " + strings.Join(m.from, ", ")}
		if c.Version != "" {
			p["versionInfo"] = c.Version
		}
		if c.Purl != "" {
			p["externalRefs"] = []map[string]any{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.Purl}}
		}
		pkgs = append(pkgs, p)
		for k := range m.edges {
			rels = append(rels, map[string]any{"spdxElementId": id(m.key), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": id(k)})
		}
		if !hasParent[m.key] {
			rels = append(rels, map[string]any{"spdxElementId": "SPDXRef-Subject", "relationshipType": "CONTAINS", "relatedSpdxElement": id(m.key)})
		}
	}
	return map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name":              subject.Name,
		"documentNamespace": fmt.Sprintf("%s/spdx/%s/%s", strings.TrimRight(namespaceBase, "/"), spdxIDUnsafe.ReplaceAllString(subject.Name, "-"), uuid.NewString()),
		"creationInfo":      map[string]any{"created": now.UTC().Format(time.RFC3339), "creators": []string{"Tool: rampart"}},
		"packages":          pkgs, "relationships": rels,
	}
}
