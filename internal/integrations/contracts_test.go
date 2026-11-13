package integrations

import (
	"context"
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

	// 2. Trackers
	trackers := reg.ListTrackers()
	if len(trackers) < 2 {
		t.Errorf("expected at least 2 trackers, got %d", len(trackers))
	}
	for _, desc := range trackers {
		tr, err := reg.GetTracker(desc.ID)
		if err != nil {
			t.Fatalf("failed to retrieve tracker %s: %v", desc.ID, err)
		}
		if tr.Descriptor().ID != desc.ID {
			t.Errorf("id mismatch: got %s, want %s", tr.Descriptor().ID, desc.ID)
		}
		if tr.Descriptor().Kind != KindTracker {
			t.Errorf("kind mismatch for %s: got %s", desc.ID, tr.Descriptor().Kind)
		}
		if len(tr.Descriptor().ConfigSchema) == 0 {
			t.Errorf("tracker %s has empty config schema", desc.ID)
		}
		if err := tr.Check(context.Background(), map[string]any{"ok": true}); err != nil {
			t.Errorf("check failed for %s: %v", desc.ID, err)
		}
		ref, err := tr.Create(context.Background(), map[string]any{}, IssueDraft{Title: "Test vulnerability"})
		if err != nil || ref.Key == "" {
			t.Errorf("create failed for %s: ref=%+v, err=%v", desc.ID, ref, err)
		}
		if err := tr.Update(context.Background(), map[string]any{}, ref, IssueDraft{Title: "Updated"}); err != nil {
			t.Errorf("update failed for %s: %v", desc.ID, err)
		}
		states, err := tr.Get(context.Background(), map[string]any{}, []IssueRef{ref})
		if err != nil || len(states) != 1 {
			t.Errorf("get failed for %s: states=%+v, err=%v", desc.ID, states, err)
		}
	}

	// 3. Notifiers
	notifiers := reg.ListNotifiers()
	if len(notifiers) < 4 {
		t.Errorf("expected at least 4 notifiers, got %d", len(notifiers))
	}
	for _, desc := range notifiers {
		n, err := reg.GetNotifier(desc.ID)
		if err != nil {
			t.Fatalf("failed to retrieve notifier %s: %v", desc.ID, err)
		}
		if n.Descriptor().ID != desc.ID {
			t.Errorf("id mismatch: got %s, want %s", n.Descriptor().ID, desc.ID)
		}
		if n.Descriptor().Kind != KindNotifier {
			t.Errorf("kind mismatch for %s: got %s", desc.ID, n.Descriptor().Kind)
		}
		if len(n.Descriptor().ConfigSchema) == 0 {
			t.Errorf("notifier %s has empty config schema", desc.ID)
		}
		if err := n.Check(context.Background(), map[string]any{"ok": true}); err != nil {
			t.Errorf("check failed for %s: %v", desc.ID, err)
		}
		if err := n.Send(context.Background(), map[string]any{}, Message{Title: "Alert", Summary: "High risk"}); err != nil {
			t.Errorf("send failed for %s: %v", desc.ID, err)
		}
	}

	// 4. Sources
	sources := reg.ListSources()
	if len(sources) < 1 {
		t.Errorf("expected at least 1 source, got %d", len(sources))
	}
	for _, desc := range sources {
		s, err := reg.GetSource(desc.ID)
		if err != nil {
			t.Fatalf("failed to retrieve source %s: %v", desc.ID, err)
		}
		if s.Descriptor().ID != desc.ID {
			t.Errorf("id mismatch: got %s, want %s", s.Descriptor().ID, desc.ID)
		}
		if s.Descriptor().Kind != KindSource {
			t.Errorf("kind mismatch for %s: got %s", desc.ID, s.Descriptor().Kind)
		}
		if len(s.Descriptor().ConfigSchema) == 0 {
			t.Errorf("source %s has empty config schema", desc.ID)
		}
		if err := s.Check(context.Background(), map[string]any{"ok": true}); err != nil {
			t.Errorf("check failed for %s: %v", desc.ID, err)
		}
		count := 0
		for _, err := range s.Discover(context.Background(), map[string]any{}) {
			if err != nil {
				t.Fatalf("discover failed: %v", err)
			}
			count++
		}
		if count == 0 {
			t.Errorf("source %s discovered 0 projects", desc.ID)
		}
	}

	// 5. ListAll
	all := reg.ListAll()
	expectedTotal := len(parsers) + len(trackers) + len(notifiers) + len(sources)
	if len(all) != expectedTotal {
		t.Errorf("ListAll() count mismatch: got %d, want %d", len(all), expectedTotal)
	}
}
