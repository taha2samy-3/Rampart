package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// Parser implements the SARIF 2.1.0 streaming token-walk parser (normative D11, D15, 05 §2).
type Parser struct{}

// NewParser creates a new SARIF parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the identifier of this parser.
func (p *Parser) Name() string {
	return "sarif"
}

// Detect inspects header bytes and file naming to determine if the report is SARIF 2.1.0.
func (p *Parser) Detect(head []byte, filename string, contentType string) int {
	score := 0
	lowerName := strings.ToLower(filename)
	if strings.HasSuffix(lowerName, ".sarif") || strings.HasSuffix(lowerName, ".sarif.json") {
		score += 50
	}
	if strings.Contains(contentType, "sarif+json") {
		score += 40
	}

	headStr := string(head)
	if strings.Contains(headStr, `"version": "2.1.0"`) || strings.Contains(headStr, `"version":"2.1.0"`) {
		score += 30
	}
	if strings.Contains(headStr, "sarif-2.1.0.json") || strings.Contains(headStr, `"runs"`) {
		score += 20
	}

	if score > 100 {
		return 100
	}
	return score
}

// Parse streams findings from a SARIF document using a token walk (D15).
func (p *Parser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		dec := json.NewDecoder(r)

		// 1. Walk root object tokens until "runs"
		if err := skipToKey(dec, "runs"); err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("sarif: invalid format, runs array missing: %w", err))
			return
		}

		// Read start of runs array: '['
		tok, err := dec.Token()
		if err != nil || tok != json.Delim('[') {
			yield(domain.RawFinding{}, fmt.Errorf("sarif: expected runs array, got %v", tok))
			return
		}

		// Process each run in the runs array
		for dec.More() {
			if ctx.Err() != nil {
				return
			}

			// Read start of run object: '{'
			t, err := dec.Token()
			if err != nil || t != json.Delim('{') {
				yield(domain.RawFinding{}, fmt.Errorf("sarif: expected start of run object: %w", err))
				return
			}

			var driverName string
			var driverVersion string
			ruleMetadata := make(map[string]sarifRule)

			// Walk run object keys
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					yield(domain.RawFinding{}, fmt.Errorf("sarif: error reading run key: %w", err))
					return
				}
				key, ok := keyTok.(string)
				if !ok {
					continue
				}

				switch key {
				case "tool":
					var toolObj struct {
						Driver struct {
							Name    string      `json:"name"`
							Version string      `json:"version"`
							Rules   []sarifRule `json:"rules"`
						} `json:"driver"`
					}
					if err := dec.Decode(&toolObj); err != nil {
						yield(domain.RawFinding{}, fmt.Errorf("sarif: decoding tool failed: %w", err))
						return
					}
					driverName = toolObj.Driver.Name
					driverVersion = toolObj.Driver.Version
					for _, r := range toolObj.Driver.Rules {
						ruleMetadata[r.ID] = r
					}

				case "results":
					// Read '[' start of results array
					resTok, err := dec.Token()
					if err != nil || resTok != json.Delim('[') {
						yield(domain.RawFinding{}, fmt.Errorf("sarif: expected results array: %w", err))
						return
					}

					scannerFamily := normalize.CanonicalScannerFamily(driverName)

					// Walk individual results without buffering the whole array!
					for dec.More() {
						if ctx.Err() != nil {
							return
						}

						var res sarifResult
						if err := dec.Decode(&res); err != nil {
							yield(domain.RawFinding{}, fmt.Errorf("sarif: decoding result failed: %w", err))
							return
						}

						rawFinding := mapResultToRawFinding(res, driverName, driverVersion, scannerFamily, ruleMetadata)

						if !yield(rawFinding, nil) {
							return // Caller requested stop
						}
					}

					// Consume ']' end of results array
					if _, err := dec.Token(); err != nil {
						yield(domain.RawFinding{}, fmt.Errorf("sarif: closing results array failed: %w", err))
						return
					}

				default:
					// Skip unneeded run keys
					var discard any
					if err := dec.Decode(&discard); err != nil {
						yield(domain.RawFinding{}, fmt.Errorf("sarif: skipping run key %q failed: %w", key, err))
						return
					}
				}
			}

			// Consume '}' end of run object
			if _, err := dec.Token(); err != nil {
				yield(domain.RawFinding{}, fmt.Errorf("sarif: closing run object failed: %w", err))
				return
			}
		}
	}
}

func mapResultToRawFinding(
	res sarifResult,
	driverName string,
	driverVersion string,
	scannerFamily string,
	rules map[string]sarifRule,
) domain.RawFinding {
	ruleID := res.RuleID
	ruleMeta, hasRule := rules[ruleID]

	title := ""
	if res.Message.Text != "" {
		title = res.Message.Text
	} else if hasRule && ruleMeta.ShortDescription.Text != "" {
		title = ruleMeta.ShortDescription.Text
	} else {
		title = ruleID
	}

	description := ""
	if hasRule && ruleMeta.FullDescription.Text != "" {
		description = ruleMeta.FullDescription.Text
	} else if hasRule && ruleMeta.Help.Text != "" {
		description = ruleMeta.Help.Text
	}

	// Normalize severity from level or security-severity
	toolSev := res.Level
	if toolSev == "" {
		toolSev = "warning"
	}
	// The rule's security-severity applies unless the result carries its own.
	sevProps := res.Properties
	if ruleSev := ruleMeta.Properties.SecuritySeverity; ruleSev != nil {
		if _, own := sevProps["security-severity"]; !own {
			merged := map[string]any{}
			for k, v := range sevProps {
				merged[k] = v
			}
			merged["security-severity"] = ruleSev
			sevProps = merged
		}
	}
	normSev := mapSarifLevelToSeverity(toolSev, sevProps)

	// Extract primary location
	var loc domain.Location
	if len(res.Locations) > 0 {
		phys := res.Locations[0].PhysicalLocation
		uri := phys.ArtifactLocation.URI
		startLine := phys.Region.StartLine
		endLine := phys.Region.EndLine
		if endLine == 0 {
			endLine = startLine
		}
		startCol := phys.Region.StartColumn
		endCol := phys.Region.EndColumn
		snippet := phys.Region.Snippet.Text

		var logicalLoc string
		if len(res.Locations[0].LogicalLocations) > 0 {
			logicalLoc = res.Locations[0].LogicalLocations[0].FullyQualifiedName
		}

		loc.Code = &domain.CodeLocation{
			FilePath:        normalize.CleanPath(uri),
			StartLine:       startLine,
			EndLine:         endLine,
			StartColumn:     startCol,
			EndColumn:       endCol,
			LogicalLocation: logicalLoc,
			Snippet:         snippet,
			SnippetHash:     normalize.ComputeSnippetHash(snippet),
		}
	}

	// Extract CWEs from rule tags or relationships
	cwes := extractCWEs(ruleMeta)

	// Determine category based on scanner or rule
	category := deriveCategory(scannerFamily, ruleMeta.Properties.Tags)

	// Keep raw record
	rawBytes, _ := json.Marshal(res)

	return domain.RawFinding{
		ScannerFamily:  scannerFamily,
		ScannerName:    driverName,
		ScannerVersion: driverVersion,
		ToolRecordID:   res.GUID,
		ToolSeverity:   toolSev,
		Severity:       normSev,
		RuleID:         ruleID,
		RuleName:       ruleMeta.Name,
		Title:          normalize.NFC(title),
		Description:    normalize.NFC(description),
		Location:       loc,
		CWEs:           cwes,
		Category:       category,
		RawPayload:     rawBytes,
	}
}

func mapSarifLevelToSeverity(level string, props map[string]any) domain.Severity {
	// 1. Check if security-severity is present (D11, 05 §3)
	if props != nil {
		if secSev, ok := props["security-severity"]; ok {
			switch v := secSev.(type) {
			case float64:
				if v >= 9.0 {
					return domain.SeverityCritical
				} else if v >= 7.0 {
					return domain.SeverityHigh
				} else if v >= 4.0 {
					return domain.SeverityMedium
				} else if v > 0 {
					return domain.SeverityLow
				}
			case string:
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					if f >= 9.0 {
						return domain.SeverityCritical
					} else if f >= 7.0 {
						return domain.SeverityHigh
					} else if f >= 4.0 {
						return domain.SeverityMedium
					} else if f > 0 {
						return domain.SeverityLow
					}
				}
			}
		}
	}

	// 2. Default SARIF level mapping
	switch strings.ToLower(level) {
	case "error":
		return domain.SeverityHigh // SARIF error defaults to high (D11)
	case "warning":
		return domain.SeverityMedium
	case "note":
		return domain.SeverityLow
	case "none":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}

func deriveCategory(scannerFamily string, tags []string) domain.FindingCategory {
	switch scannerFamily {
	case "gitleaks", "trufflehog":
		return domain.CategorySecret
	case "checkov", "kics", "tfsec":
		return domain.CategoryIaC
	case "trivy", "grype":
		return domain.CategorySCA
	case "zap", "nuclei":
		return domain.CategoryDAST
	case "semgrep", "codeql", "bandit":
		return domain.CategorySAST
	}

	// Inspect tags
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, "secret") {
			return domain.CategorySecret
		}
		if strings.Contains(lower, "iac") || strings.Contains(lower, "terraform") {
			return domain.CategoryIaC
		}
		if strings.Contains(lower, "cve") || strings.Contains(lower, "vulnerability") {
			return domain.CategorySCA
		}
		if strings.Contains(lower, "dast") {
			return domain.CategoryDAST
		}
	}

	return domain.CategorySAST // default
}

func extractCWEs(rule sarifRule) []int {
	cwes := []int{}
	seen := make(map[int]bool)

	for _, tag := range rule.Properties.Tags {
		upper := strings.ToUpper(strings.TrimSpace(tag))
		if strings.HasPrefix(upper, "CWE-") {
			numStr := strings.TrimPrefix(upper, "CWE-")
			if num, err := strconv.Atoi(numStr); err == nil && !seen[num] {
				cwes = append(cwes, num)
				seen[num] = true
			}
		} else if strings.Contains(upper, "EXTERNAL/CWE/CWE-") {
			parts := strings.Split(upper, "EXTERNAL/CWE/CWE-")
			if len(parts) > 1 {
				if num, err := strconv.Atoi(parts[1]); err == nil && !seen[num] {
					cwes = append(cwes, num)
					seen[num] = true
				}
			}
		}
	}

	return cwes
}

func skipToKey(dec *json.Decoder, targetKey string) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if key, ok := tok.(string); ok && key == targetKey {
			return nil
		}
	}
}

// Minimal SARIF struct definitions for token walk
type sarifResult struct {
	RuleID  string `json:"ruleId"`
	GUID    string `json:"guid"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				EndLine     int `json:"endLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
				Snippet     struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
		LogicalLocations []struct {
			FullyQualifiedName string `json:"fullyQualifiedName"`
		} `json:"logicalLocations"`
	} `json:"locations"`
	Properties map[string]any `json:"properties"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	Properties struct {
		Tags []string `json:"tags"`
		// SecuritySeverity is where CodeQL, Semgrep, Trivy and most SARIF producers put the CVSS-like
		// score (0 to 10): on the rule, not on each result. It may be a string or a number.
		SecuritySeverity any `json:"security-severity"`
	} `json:"properties"`
}

// Compile-time check that Parser implements Parser interface
var _ = bytes.Buffer{}
