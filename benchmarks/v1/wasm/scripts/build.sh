#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wasm_root="$(cd "${script_dir}/.." && pwd)"
benchmark_root="$(cd "${wasm_root}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
generated_dir="${wasm_root}/generated/provekit"
dist_dir="${wasm_root}/dist"
cargo_target="${repo_root}/target/v1-benchmarks/wasm-single/cargo"
wasm_binary="${cargo_target}/wasm32-unknown-unknown/release/provekit_wasm.wasm"
artifact_dir="${repo_root}/target/v1-benchmarks/artifacts/webauthn_assertion"

for command in bun cargo; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${benchmark_root}/scripts/build-provekit-webauthn.sh"
wasm_bindgen="$("${benchmark_root}/scripts/bootstrap-wasm-bindgen.sh")"
(
  cd "${wasm_root}"
  bun install --frozen-lockfile
)

mkdir -p "${generated_dir}" "${dist_dir}/assets"
RUSTFLAGS="-C link-arg=--max-memory=4294967296" \
  CARGO_TARGET_DIR="${cargo_target}" \
  cargo build \
    --release \
    --target wasm32-unknown-unknown \
    -p provekit-wasm \
    --no-default-features \
    -Z build-std=panic_abort,std

"${wasm_bindgen}" \
  --target web \
  --out-dir "${generated_dir}" \
  --out-name provekit_wasm \
  "${wasm_binary}"

(
  cd "${wasm_root}"
  bun build src/runner.ts src/worker.ts \
    --outdir dist \
    --target browser \
    --format esm \
    --minify
)

cp "${wasm_root}/index.html" "${dist_dir}/index.html"
cp "${artifact_dir}/webauthn_assertion.pkp" "${dist_dir}/assets/webauthn_assertion.pkp"
cp "${artifact_dir}/webauthn_assertion.pkv" "${dist_dir}/assets/webauthn_assertion.pkv"
cp "${benchmark_root}/noir/webauthn_assertion/inputs.json" "${dist_dir}/assets/inputs.json"
cp "${generated_dir}/provekit_wasm_bg.wasm" "${dist_dir}/provekit_wasm_bg.wasm"
cp "${wasm_root}/node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm" \
  "${dist_dir}/acvm_js_bg.wasm"
cp "${wasm_root}/node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm" \
  "${dist_dir}/noirc_abi_wasm_bg.wasm"

(
  cd "${repo_root}"
  "${benchmark_root}/scripts/measure-bundle.sh" \
    "${benchmark_root}/manifests/webauthn-provekit-wasm.tsv" \
    "${dist_dir}/manifest.json"
)

echo "Built single-thread browser benchmark at ${dist_dir}"
