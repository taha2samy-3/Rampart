#!/usr/bin/env bash
# Builds the WASM parser modules that the Go tests run, from the two parser repositories, and prints the directory they are in.
# Rampart holds no parser: its tests install the default manifests from internal/testdata/parsers and run the modules these
# repositories build, with the command their own CI uses.
#
#   export RAMPART_WASM_DIR=$(hack/test-modules.sh)                       # ../parsers and ../sbom-parsers
#   export RAMPART_WASM_DIR=$(hack/test-modules.sh ~/src/parsers ~/src/sbom-parsers)
#
# OUT overrides the output directory (default .cache/wasm under this repository). A module is rebuilt only when a Go file of its
# repository is newer than it. Progress goes to stderr, so the printed directory is the only thing on stdout.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
parsers=$(cd "${1:-$here/../parsers}" && pwd)
sbom=$(cd "${2:-$here/../sbom-parsers}" && pwd)
out=${OUT:-$here/.cache/wasm}
mkdir -p "$out"

build() { # build <repository> <module directory name>
  local repo=$1 name=$2 dir="$1/wasm/$2" target="$out/$2/parser.wasm"
  [[ -f "$dir/main.go" ]] || return 0
  if [[ -f "$target" && -z "$(find "$repo" \( -name '*.go' -o -name go.mod -o -name go.sum \) -newer "$target" -print -quit)" ]]; then
    return 0
  fi
  mkdir -p "$out/$name"
  echo "building $name" >&2
  (cd "$dir" && GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "$target" .)
}

for d in "$parsers"/wasm/*/; do build "$parsers" "$(basename "$d")"; done
for d in "$sbom"/wasm/*/; do build "$sbom" "$(basename "$d")"; done
echo "$out"
