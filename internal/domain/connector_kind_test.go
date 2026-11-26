package domain_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"rampart/internal/domain"
)

// connectorTypesDeclared reads every constant of type ConnectorType from connector.go, so a type added there is
// checked here without anyone remembering to list it.
func connectorTypesDeclared(t *testing.T) []domain.ConnectorType {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "connector.go", nil, 0)
	if err != nil {
		t.Fatalf("parse connector.go: %v", err)
	}
	var out []domain.ConnectorType
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "ConnectorType" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", lit.Value, err)
				}
				out = append(out, domain.ConnectorType(s))
			}
		}
	}
	if len(out) < 8 {
		t.Fatalf("found %d ConnectorType constants in connector.go; the parser no longer sees them", len(out))
	}
	return out
}

// docs/50 step 1: GET /api/v1/connectors says each connector's kind, from the catalogue, so the UI files trackers
// and notifiers without a list of its own. Every type the server accepts must have one; a type it refuses as not
// supported must not be in the catalogue.
func TestEveryConnectorTypeHasACatalogueKind(t *testing.T) {
	valid := map[string]bool{domain.ConnectorKindTracker: true, domain.ConnectorKindNotifier: true, domain.ConnectorKindSource: true}
	for _, typ := range connectorTypesDeclared(t) {
		c := domain.Connector{Name: "probe", Type: typ}
		err := c.Validate()
		kind := domain.ConnectorKindOf(typ)
		if errors.Is(err, domain.ErrConnectorNotSupported) {
			if kind != "" {
				t.Errorf("%s is refused as not supported but the catalogue lists it as %q", typ, kind)
			}
			continue
		}
		if !valid[kind] {
			t.Errorf("%s is accepted by Validate but has catalogue kind %q; add it to the catalogue with tracker, notifier or source", typ, kind)
		}
	}
}

func TestCatalogueKindsAreKnown(t *testing.T) {
	for _, e := range domain.ConnectorCatalogue() {
		if got := domain.ConnectorKindOf(e.Type); got != e.Kind {
			t.Errorf("ConnectorKindOf(%s) = %q, catalogue says %q", e.Type, got, e.Kind)
		}
		switch e.Kind {
		case domain.ConnectorKindTracker, domain.ConnectorKindNotifier, domain.ConnectorKindSource:
		default:
			t.Errorf("%s has kind %q", e.Type, e.Kind)
		}
	}
	if got := domain.ConnectorKindOf(domain.ConnectorTypeJira); got != domain.ConnectorKindTracker {
		t.Errorf("jira: %q", got)
	}
	if got := domain.ConnectorKindOf(domain.ConnectorTypeSlack); got != domain.ConnectorKindNotifier {
		t.Errorf("slack: %q", got)
	}
	if got := domain.ConnectorKindOf(domain.ConnectorTypeGitLab); got != "" {
		t.Errorf("gitlab is deferred and has no kind, got %q", got)
	}
}
