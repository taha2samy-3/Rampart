#!/usr/bin/env python3
"""Print the SHA-256 of every compiled parser module of a parsers repository, as the values.yaml block the chart wants.

    python3 hack/wasm-modules.py ../parsers          # wasm/<name>/parser.wasm
    python3 hack/wasm-modules.py ../sbom-parsers

The digest of the IMAGE (the ghcr.io/...@sha256: reference) is a different number: take it from the registry or from the
publish job's output. This script prints the digest of the parser.wasm file the server checks at start-up (docs/35 B1).
"""
import hashlib
import pathlib
import sys

if len(sys.argv) != 2:
    sys.exit(__doc__)
root = pathlib.Path(sys.argv[1]) / "wasm"
if not root.is_dir():
    sys.exit(f"{root} is not a directory")
for mod in sorted(root.glob("*/parser.wasm")):
    digest = hashlib.sha256(mod.read_bytes()).hexdigest()
    print(f'    {mod.parent.name}: {{image: "", sha256: "{digest}"}}')
