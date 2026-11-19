package targets

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"rampart/internal/config/parsers"
	"rampart/internal/config/sbomparsers"
	"rampart/internal/wasmstore"
)

// shippedWasmModules names the WASM modules of the parsers the server ships: the report parsers whose runtime is wasm
// and the SBOM readers (docs/35 B1).
func shippedWasmModules() []string {
	set := map[string]bool{}
	if ps, err := parsers.ListDefaultParsers(); err == nil {
		for _, p := range ps {
			var m struct {
				Spec struct {
					Runtime string `yaml:"runtime"`
				} `yaml:"spec"`
			}
			if yaml.Unmarshal(p.Spec, &m) == nil && m.Spec.Runtime == "wasm" {
				set[p.Name] = true
			}
		}
	}
	if ss, err := sbomparsers.ListDefaultSBOMParsers(); err == nil {
		for _, s := range ss {
			n := s.Name
			if !strings.HasPrefix(n, "sbom-") {
				n = "sbom-" + n // the module is named like its directory in the parsers repository
			}
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// verifyWasmModules is the start-up check of the shipped modules. With a digest table in force (RAMPART_WASM_DIGESTS) a
// missing, unlisted or changed module stops the server here, not at the first upload; without one (development, tests)
// it only says so.
func (r *Runner) verifyWasmModules() error {
	if err := wasmstore.DefaultError(); err != nil {
		return err
	}
	st := wasmstore.Default()
	if !st.Strict() {
		r.logger.Warn("no WASM digest table is in force (RAMPART_WASM_DIGESTS): the shipped parser modules are found in the working directory and are not verified; set it in production")
		return nil
	}
	names := shippedWasmModules()
	if err := st.Verify(names); err != nil {
		return fmt.Errorf("shipped parser modules: %w", err)
	}
	r.logger.Info("shipped parser modules verified against the digest table", "modules", len(names), "dir", st.Dir)
	return nil
}
