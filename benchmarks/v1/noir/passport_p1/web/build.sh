#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
web_root="${root}/benchmarks/v1/noir/passport_p1/web"
dist="${web_root}/dist"
barretenberg="${root}/benchmarks/v1/barretenberg"
rm -rf "${dist}"
mkdir -p "${dist}/assets/passport_p1" "${dist}/vendor"
(
  cd "${barretenberg}"
  bun build "${web_root}/runner.ts" --outdir "${dist}" --target browser --format esm --minify --external '*vendor/bb/index.js'
  bun run inputs -- "${root}/benchmarks/v1/noir/passport_p1/Prover.toml" "${dist}/assets/passport_p1/inputs.json"
)
cp "${web_root}/index.html" "${dist}/index.html"
cp -R "${barretenberg}/web/dist/vendor/bb" "${dist}/vendor/bb"
cp "${barretenberg}/node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm" "${dist}/acvm_js_bg.wasm"
cp "${barretenberg}/node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm" "${dist}/noirc_abi_wasm_bg.wasm"
cp "${root}/benchmarks/v1/noir/passport_p1/target/passport_p1.json" "${dist}/assets/passport_p1/circuit.json"
