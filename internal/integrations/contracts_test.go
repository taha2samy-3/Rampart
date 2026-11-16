package integrations

import (
	"testing"
)

func TestRegistry_AllBuiltinContracts(t *testing.T) {
	reg := DefaultRegistry()

	// 1. Parsers
	parsers := reg.ListParsers()
	if len(parsers) < 10 {
		t.Errorf("expected at least 10 parsers, got %d", len(parsers))
	}
	for _, desc := range parsers {
		p, err := reg.GetParser(desc.ID)
		if err != nil {
			t.Fatalf("failed to retrieve parser %s: %v", desc.ID, err)
		}
		if p.Descriptor().ID != desc.ID {
			t.Errorf("id mismatch: got %s, want %s", p.Descriptor().ID, desc.ID)
		}
		if p.Descriptor().Kind != KindParser {
			t.Errorf("kind mismatch for %s: got %s", desc.ID, p.Descriptor().Kind)
		}
	}
}
