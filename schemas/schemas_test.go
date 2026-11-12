package schemas_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalSchemas(t *testing.T) {
	schemas := []string{
		"rawfinding.v1.json",
		"issuedraft.v1.json",
		"message.v1.json",
		"upstreamproject.v1.json",
	}

	for _, name := range schemas {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(".", name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read schema file %q: %v", name, err)
			}

			var schemaObj map[string]any
			if err := json.Unmarshal(data, &schemaObj); err != nil {
				t.Fatalf("schema %q is not valid JSON: %v", name, err)
			}

			// Validate presence of fundamental JSON Schema fields
			if _, ok := schemaObj["$schema"]; !ok {
				t.Errorf("schema %q missing $schema", name)
			}
			if _, ok := schemaObj["$id"]; !ok {
				t.Errorf("schema %q missing $id", name)
			}
			if _, ok := schemaObj["title"]; !ok {
				t.Errorf("schema %q missing title", name)
			}
			if _, ok := schemaObj["type"]; !ok {
				t.Errorf("schema %q missing type", name)
			}
			if _, ok := schemaObj["properties"]; !ok {
				t.Errorf("schema %q missing properties", name)
			}
		})
	}
}
