package targets

import (
	"fmt"
	"sort"

	"rampart/internal/wasmstore"
)

// expectedWasmModules names the WASM modules the server must find at start-up. The server knows no parser by name, so the
// digest table is the list: it names what the deployment published, and each one must be present and match (docs/35 B1).
func expectedWasmModules(st *wasmstore.Store) []string {
	out := make([]string, 0, len(st.Digests))
	for n := range st.Digests {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// verifyWasmModules is the start-up check of the published modules. With a digest table in force (RAMPART_WASM_DIGESTS) a
// module the table lists that is missing or changed stops the server here, not at the first upload; a parser installed with
// a module the table does not list is refused when it is used, so it is never run unverified. Without a table (development,
// tests) the check only says so.
func (r *Runner) verifyWasmModules() error {
	if err := wasmstore.DefaultError(); err != nil {
		return err
	}
	st := wasmstore.Default()
	if !st.Strict() {
		r.logger.Warn("no WASM digest table is in force (RAMPART_WASM_DIGESTS): the parser modules are found in the working directory and are not verified; set it in production")
		return nil
	}
	names := expectedWasmModules(st)
	if err := st.Verify(names); err != nil {
		return fmt.Errorf("parser modules: %w", err)
	}
	r.logger.Info("parser modules verified against the digest table", "modules", len(names), "dir", st.Dir)
	return nil
}
