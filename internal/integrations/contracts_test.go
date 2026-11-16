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

	// Trackers, notifiers and sources: none registered until the real implementations are (D82, docs/23 §6). The
	// placeholders that were registered are gone; this keeps them from coming back unnoticed.
	if n := len(reg.ListTrackers()) + len(reg.ListNotifiers()) + len(reg.ListSources()); n != 0 {
		t.Errorf("expected no placeholder trackers, notifiers or sources, got %d", n)
	}

	// 5. ListAll
	all := reg.ListAll()
	expectedTotal := len(parsers)
	if len(all) != expectedTotal {
		t.Errorf("ListAll() count mismatch: got %d, want %d", len(all), expectedTotal)
	}
}
