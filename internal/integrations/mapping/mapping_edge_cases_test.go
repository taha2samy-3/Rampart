package mapping_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations/mapping"
)

// TestMappingParser_SyntaxAndCompilation_EdgeCases tests invalid packages, syntax errors,
// and invalid CEL types.
func TestMappingParser_SyntaxAndCompilation_EdgeCases(t *testing.T) {
	t.Run("invalid YAML fails initialization with error", func(t *testing.T) {
		badYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
spec: [invalid yaml structure: {{{
`
		_, err := mapping.NewMappingParser([]byte(badYAML))
		if err == nil {
			t.Fatal("expected error for invalid YAML")
		}
	})

	t.Run("CEL syntax error fails initialization with clear message", func(t *testing.T) {
		badCEL := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: test-scanner
  category: sast
  input:
    format: json
    records: $.items[*]
  map:
    ruleId: 'rec.id ++++ invalid syntax'
`
		_, err := mapping.NewMappingParser([]byte(badCEL))
		if err == nil {
			t.Fatal("expected error for CEL syntax error")
		}
	})

	t.Run("division by zero in CEL expression is trapped without panicking", func(t *testing.T) {
		divZeroYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: test-zero
  category: sast
  input:
    format: json
    records: $.items[*]
  map:
    ruleId: 'string(10 / 0)'
    title: rec.title
`
		parser, err := mapping.NewMappingParser([]byte(divZeroYAML))
		if err != nil {
			// Some CEL compilers reject constant division by zero at compile time
			return
		}

		sample := `{"items":[{"title":"Vuln 1"}]}`
		// Parsing must not panic
		for _, parseErr := range parser.Parse(context.Background(), strings.NewReader(sample), domain.ParseContext{}) {
			// An error during parse for the record is expected
			_ = parseErr
		}
	})
}

// TestMappingParser_LimitsAndBounds_EdgeCases tests maxRecords limits,
// detection corner cases, and null fields.
func TestMappingParser_LimitsAndBounds_EdgeCases(t *testing.T) {
	pkgYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: bounded-scanner
  category: sca
  detect:
    filenames: ["scan-*.json"]
    probes:
      - jsonHasKeys: [results, scanner]
  input:
    format: json
    records: $.results[*]
  map:
    ruleId:       rec.id
    title:        rec.title
    severity:     rec.severity
    toolRecordId: rec.id
  severityMap:
    CRITICAL: critical
    HIGH:     high
    MEDIUM:   medium
    LOW:      low
  limits:
    maxRecords: 5
`
	parser, err := mapping.NewMappingParser([]byte(pkgYAML))
	if err != nil {
		t.Fatalf("failed initializing parser: %v", err)
	}

	t.Run("empty or corrupted payload in Detect does not panic", func(t *testing.T) {
		score := parser.Detect([]byte{}, "test.json", "application/json")
		if score != 0 {
			t.Errorf("expected score 0 for empty payload, got %d", score)
		}

		scoreCorrupt := parser.Detect([]byte(`{corrupt json...`), "test.json", "application/json")
		if scoreCorrupt != 0 {
			t.Errorf("expected score 0 for corrupt json, got %d", scoreCorrupt)
		}
	})

	t.Run("maxRecords limit stops processing after 5 items", func(t *testing.T) {
		// Create JSON with 20 items
		var items []string
		for i := 0; i < 20; i++ {
			items = append(items, fmt.Sprintf(`{"id":"R-%d","title":"Vuln %d","severity":"HIGH"}`, i, i))
		}
		jsonBody := fmt.Sprintf(`{"results": [%s]}`, strings.Join(items, ","))

		var count int
		for _, parseErr := range parser.Parse(context.Background(), strings.NewReader(jsonBody), domain.ParseContext{}) {
			if parseErr == nil {
				count++
			}
		}

		if count > 5 {
			t.Fatalf("expected at most 5 records due to maxRecords limit, got %d", count)
		}
	})

	t.Run("unknown severity maps to info or default", func(t *testing.T) {
		jsonBody := `{"results": [{"id":"R-99","title":"Vuln","severity":"EXTRA_EXTREME"}]}`
		var found domain.RawFinding
		for f, parseErr := range parser.Parse(context.Background(), strings.NewReader(jsonBody), domain.ParseContext{}) {
			if parseErr == nil {
				found = f
				break
			}
		}

		if found.Severity == "" {
			t.Fatal("expected severity to have a valid fallback value")
		}
	})
}
