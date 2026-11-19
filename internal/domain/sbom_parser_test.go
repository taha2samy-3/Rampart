package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateClusterSBOMParserSpec(t *testing.T) {
	good := `{"format":"spdx","runtime":"wasm","source":{"oci":"ghcr.io/x/sbom-spdx:v1"}}`
	for _, c := range []struct {
		name, spec, want string // want is a part of the error, empty for valid
	}{
		{"sbom-spdx", good, ""},
		{"sbom-my.reader_2", `{"format":"my.reader_2","runtime":"wasm"}`, ""},
		{"spdx", good, `starts with "sbom-"`},
		{"sbom-", good, `starts with "sbom-"`},
		{"sbom-x", `{"format":"","runtime":"wasm"}`, "format"},
		{"sbom-x", `{"format":"SPDX","runtime":"wasm"}`, "format"},
		{"sbom-x", `{"format":"spdx","runtime":"lua"}`, "only wasm"},
		{"sbom-x", `{"format":"spdx"}`, "only wasm"},
		{"sbom-x", `not json`, "not a valid"},
	} {
		err := ValidateClusterSBOMParserSpec(c.name, []byte(c.spec))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s %s: unexpected error %v", c.name, c.spec, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s %s: want an error with %q, got %v", c.name, c.spec, c.want, err)
		}
	}
}

func TestStoredSBOMParserKeepsKindAndSpec(t *testing.T) {
	spec := `{"format":"spdx","runtime":"wasm","detect":{"filenames":["*.spdx"]}}`
	var got struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(StoredSBOMParser("sbom-spdx", []byte(spec)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != "ClusterSBOMParser" || got.Metadata.Name != "sbom-spdx" || got.Spec["format"] != "spdx" || got.Spec["detect"] == nil {
		t.Fatalf("stored form lost something: %+v", got)
	}
	// A spec that is not JSON is kept as it is, with the reason it was refused stored beside it.
	if string(StoredSBOMParser("sbom-x", []byte("not json"))) != "not json" {
		t.Error("a spec that is not JSON must be returned unchanged")
	}
}
