#!/usr/bin/env bash
# Puts the default parsers where this quick start reads them: ./parsers (the manifests, RAMPART_PARSERS_DIR) and ./wasm (the
# modules, RAMPART_WASM_DIR). Rampart holds no parser: they come from the two parser repositories.
#
#   ./fetch-parsers.sh                                    # clones Rampart-Aspm/parsers and Rampart-Aspm/sbom-parsers, builds the modules
#   ./fetch-parsers.sh ~/src/parsers ~/src/sbom-parsers   # uses checkouts you already have
#
# It needs git (to clone) and Go (to build the modules). PARSERS_REF picks the branch or tag to clone (default main). Run it before
# `docker compose up`, and again to update; the directories it fills are git-ignored.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ref=${PARSERS_REF:-main}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
parsers=${1:-}; sbom=${2:-}
[[ -n "$parsers" ]] || { git clone --quiet --depth 1 --branch "$ref" https://github.com/Rampart-Aspm/parsers.git "$work/parsers"; parsers=$work/parsers; }
[[ -n "$sbom" ]] || { git clone --quiet --depth 1 --branch "$ref" https://github.com/Rampart-Aspm/sbom-parsers.git "$work/sbom-parsers"; sbom=$work/sbom-parsers; }
parsers=$(cd "$parsers" && pwd); sbom=$(cd "$sbom" && pwd)

modules=$(OUT="$work/wasm" "$root/hack/test-modules.sh" "$parsers" "$sbom")

# keep .gitkeep, replace the rest
find "$here/parsers" "$here/wasm" -mindepth 1 ! -name .gitkeep -delete
for f in "$parsers"/wasm/*/parser.yaml "$parsers"/lua/*/parser.yaml "$sbom"/wasm/*/parser.yaml; do
  [[ -f "$f" ]] || continue
  cp "$f" "$here/parsers/$(basename "$(dirname "$f")").yaml"
done
for d in "$modules"/*/; do
  mkdir -p "$here/wasm/$(basename "$d")"
  cp "$d/parser.wasm" "$here/wasm/$(basename "$d")/parser.wasm"
done
echo "parsers: $(find "$here/parsers" -name '*.yaml' | wc -l) manifests in deploy/compose/parsers, $(find "$here/wasm" -name parser.wasm | wc -l) modules in deploy/compose/wasm"
