package sbom

import "rampart/internal/integrations"

// The SBOM reader a ClusterSBOMParser describes is built here; internal/integrations cannot import this package, so it is
// registered the way the Lua and WASM report runtimes are.
func init() {
	integrations.SBOMParserLoader = func(name string, raw []byte) (integrations.ParserContract, error) {
		p, err := NewWasmSBOMParserFromSpec(name, raw, nil)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
}
