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

for command in bun cargo; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${benchmark_root}/scripts/compile-noir-workloads.sh"
for workload in webauthn_assertion passport_complete_age_check oprf_taceo; do
  V1_BENCHMARK_SKIP_NOIR_COMPILE=1 \
    "${benchmark_root}/scripts/build-provekit-workload.sh" "${workload}"
done
wasm_bindgen="$("${benchmark_root}/scripts/bootstrap-wasm-bindgen.sh")"
(
  cd "${wasm_root}"
  bun install --frozen-lockfile
)

if [[ "${dist_dir}" != "${repo_root}/benchmarks/v1/wasm/dist" ]]; then
  echo "error: refusing to clean unexpected dist path ${dist_dir}" >&2
  exit 1
fi
rm -rf "${dist_dir}"
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
for workload in webauthn_assertion passport_complete_age_check oprf_taceo; do
  workload_dir="${repo_root}/target/v1-benchmarks/artifacts/${workload}"
  asset_dir="${dist_dir}/assets/${workload}"
  mkdir -p "${asset_dir}"
  cp "${workload_dir}/${workload}.pkp" "${asset_dir}/${workload}.pkp"
  cp "${workload_dir}/${workload}.pkv" "${asset_dir}/${workload}.pkv"
done
cp "${benchmark_root}/noir/webauthn_assertion/inputs.json" \
  "${dist_dir}/assets/webauthn_assertion/inputs.json"
(
  cd "${benchmark_root}/barretenberg"
  bun run inputs -- \
    "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml" \
    "${dist_dir}/assets/passport_complete_age_check/inputs.json"
  bun run inputs -- \
    "${repo_root}/target/v1-benchmarks/sources/oprf-nr/oprf_example/Prover.toml" \
    "${dist_dir}/assets/oprf_taceo/inputs.json"
)
cp "${generated_dir}/provekit_wasm_bg.wasm" "${dist_dir}/provekit_wasm_bg.wasm"
cp "${wasm_root}/node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm" \
  "${dist_dir}/acvm_js_bg.wasm"
cp "${wasm_root}/node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm" \
  "${dist_dir}/noirc_abi_wasm_bg.wasm"

(
  cd "${repo_root}"
  "${benchmark_root}/scripts/measure-bundle.sh" \
    "${benchmark_root}/manifests/provekit-wasm-workloads.tsv" \
    "${dist_dir}/manifest.json"
)

echo "Built single-thread browser benchmark at ${dist_dir}"
