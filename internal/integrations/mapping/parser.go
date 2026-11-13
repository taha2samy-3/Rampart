package mapping

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"path/filepath"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/integrations"
)

// MappingParser adapts a compiled declarative mapping into a ParserContract (docs/19 §4).
type MappingParser struct {
	cm   *CompiledMapping
	desc integrations.Descriptor
}

// NewMappingParser creates a parser contract from YAML definition.
func NewMappingParser(yamlData []byte) (*MappingParser, error) {
	pkg, err := LoadMappingYAML(yamlData)
	if err != nil {
		return nil, err
	}

	cm, err := Compile(pkg)
	if err != nil {
		return nil, err
	}

	desc := integrations.Descriptor{
		ID:           "mapping:" + pkg.Metadata.Name,
		Name:         pkg.Metadata.Name + " (Declarative)",
		Kind:         integrations.KindParser,
		Version:      pkg.Spec.Version,
		SupportLevel: integrations.SupportCertified,
		Description:  fmt.Sprintf("Declarative mapping parser for %s (%s)", pkg.Spec.Family, pkg.Spec.Category),
	}

	return &MappingParser{
		cm:   cm,
		desc: desc,
	}, nil
}

func (p *MappingParser) Descriptor() integrations.Descriptor {
	return p.desc
}

func (p *MappingParser) Detect(head []byte, filename string, contentType string) int {
	spec := p.cm.pkg.Spec.Detect

	// 1. Filename match
	base := filepath.Base(filename)
	filenameMatched := false
	for _, pattern := range spec.Filenames {
		if matched, _ := filepath.Match(pattern, base); matched {
			filenameMatched = true
			break
		}
	}

	// 2. Probes (jsonHasKeys)
	probesMatched := false
	if len(spec.Probes) > 0 {
		for _, probe := range spec.Probes {
			if len(probe.JSONHasKeys) > 0 {
				allKeysPresent := true
				for _, k := range probe.JSONHasKeys {
					keyPattern := []byte(`"` + k + `"`)
					if !bytes.Contains(head, keyPattern) {
						allKeysPresent = false
						break
					}
				}
				if allKeysPresent {
					probesMatched = true
					break
				}
			}
		}
	}

	if filenameMatched && probesMatched {
		return 95
	}
	if filenameMatched {
		return 75
	}
	if probesMatched {
		return 80
	}
	return 0
}

func (p *MappingParser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		pkg := p.cm.pkg
		parentVar := "dep"
		if pkg.Spec.Input.Parent != "" {
			parentVar = pkg.Spec.Input.Parent
		}

		stream := StreamRecords(ctx, r, pkg.Spec.Input.Records, parentVar, pkg.Spec.Limits.MaxRecords, pkg.Spec.Limits.MaxDepth)

		recordIdx := 0
		for item, err := range stream {
			if err != nil {
				if pc.RecordError != nil {
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("%s[%d]", pkg.Spec.Input.Records, recordIdx),
						Message: err.Error(),
					})
					recordIdx++
					continue
				}
				yield(domain.RawFinding{}, err)
				return
			}

			recordIdx++

			// Build CEL evaluation vars
			vars := map[string]any{
				"rec":     item.Rec,
				parentVar: item.Parent,
				"doc":     item.Doc,
				"ctx": map[string]any{
					"branch":       pc.UploadContext.Branch,
					"commit":       pc.UploadContext.Commit,
					"pipeline_url": pc.UploadContext.PipelineURL,
				},
			}

			ruleID := p.cm.EvalString(p.cm.ruleID, vars)
			title := p.cm.EvalString(p.cm.title, vars)

			if ruleID == "" || title == "" {
				if pc.RecordError != nil {
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("%s[%d]", pkg.Spec.Input.Records, recordIdx-1),
						Message: fmt.Sprintf("missing ruleId (%q) or title (%q)", ruleID, title),
					})
					continue
				}
			}

			desc := p.cm.EvalString(p.cm.desc, vars)
			rawSev := p.cm.EvalString(p.cm.severity, vars)
			toolRecordID := p.cm.EvalString(p.cm.toolRecordID, vars)
			vulnIDs := p.cm.EvalStringSlice(p.cm.vulnIDs, vars)

			// Map tool severity to normalized severity
			var normSev domain.Severity
			if mapped, ok := pkg.Spec.SeverityMap[rawSev]; ok {
				normSev = domain.ParseSeverity(mapped)
			} else {
				normSev = domain.ParseSeverity(rawSev)
			}
			if normSev == "" {
				normSev = domain.SeverityUnknown
			}

			// Map location
			file := p.cm.EvalString(p.cm.file, vars)
			startLine := p.cm.EvalInt(p.cm.startLine, vars)
			purl := p.cm.EvalString(p.cm.purl, vars)
			pkgName := p.cm.EvalString(p.cm.pkgName, vars)
			installedVer := p.cm.EvalString(p.cm.installedVer, vars)
			fixedVer := p.cm.EvalString(p.cm.fixedVer, vars)

			var loc domain.Location
			if file != "" {
				loc.Code = &domain.CodeLocation{
					FilePath:  file,
					StartLine: startLine,
				}
			}
			if purl != "" || pkgName != "" || installedVer != "" || fixedVer != "" {
				loc.Package = &domain.PackageLocation{
					Purl:             purl,
					ComponentName:    pkgName,
					InstalledVersion: installedVer,
					FixedVersion:     fixedVer,
				}
			}

			cat := domain.FindingCategory(strings.ToLower(pkg.Spec.Category))
			if cat == "" {
				cat = domain.CategorySAST
			}

			rawPayload, _ := json.Marshal(item.Rec)

			rf := domain.RawFinding{
				RuleID:        ruleID,
				ScannerFamily: pkg.Spec.Family,
				Category:      cat,
				ToolRecordID:  toolRecordID,
				ToolSeverity:  rawSev,
				Severity:      normSev,
				Title:         title,
				Description:   desc,
				Location:      loc,
				VulnIDs:       vulnIDs,
				RawPayload:    rawPayload,
			}

			if !yield(rf, nil) {
				return
			}
		}
	}
}
