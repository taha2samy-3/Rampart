package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

// D82: every connector example the UI shows is a resource the server accepts. The example is applied through the
// same library the operator and `rampart apply` use; a drift between the catalogue and the validation fails here.
func TestConnectorCatalogueExamplesApply(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"cat"},"spec":{"namespaces":["cat-ns"]}}`)); err != nil {
		t.Fatal(err)
	}
	entries := domain.ConnectorCatalogue()
	if len(entries) != 7 {
		t.Fatalf("expected 7 connector types, got %d", len(entries))
	}
	for _, e := range entries {
		if e.ConfigSchema["type"] != "object" || len(e.Secrets) == 0 {
			t.Errorf("%s: incomplete entry", e.Type)
		}
		doc := strings.SplitN(e.Example, "\n---\n", 2)[0]
		doc = strings.ReplaceAll(doc, "<tenant-namespace>", "cat-ns")
		if _, err := applier.ApplyDocument(ctx, []byte(doc)); err != nil {
			t.Errorf("%s: the catalogue example is refused by the server: %v", e.Type, err)
		}
		if !strings.Contains(e.Example, "kind: Secret") || strings.Contains(strings.ToLower(e.Example), "password: p") {
			t.Errorf("%s: the example must carry a Secret template with placeholders only", e.Type)
		}
	}
}
