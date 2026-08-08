#!/usr/bin/env bash

set -euo pipefail

web_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
barretenberg_root="$(cd "${web_root}/.." && pwd)"
benchmark_root="$(cd "${barretenberg_root}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
dist="${web_root}/dist"

for command in bun cp mkdir; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

(
  cd "${barretenberg_root}"
  bun install --frozen-lockfile
)

if [[ "${dist}" != "${repo_root}/benchmarks/v1/barretenberg/web/dist" ]]; then
  echo "error: refusing to clean unexpected dist path ${dist}" >&2
  exit 1
fi
rm -rf "${dist}"
mkdir -p "${dist}/vendor/bb" "${dist}/assets"

(
  cd "${barretenberg_root}"
  bun build web/runner.ts \
    --outdir web/dist \
    --target browser \
    --format esm \
    --minify \
    --external '*vendor/bb/index.js'
)
cp "${web_root}/index.html" "${dist}/index.html"
(
  cd "${barretenberg_root}"
  bun build node_modules/@aztec/bb.js/dest/browser/index.js \
    --outdir web/dist/vendor/bb \
    --target browser \
    --format esm \
    --splitting
)
cp "${barretenberg_root}/node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm" \
  "${dist}/acvm_js_bg.wasm"
cp "${barretenberg_root}/node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm" \
  "${dist}/noirc_abi_wasm_bg.wasm"

copy_workload() {
  local workload="$1"
  local circuit="$2"
  local inputs="$3"
  local asset_dir="${dist}/assets/${workload}"
  mkdir -p "${asset_dir}"
  cp "${circuit}" "${asset_dir}/circuit.json"
  if [[ "${inputs}" == *.toml ]]; then
    (
      cd "${barretenberg_root}"
      bun run inputs -- "${inputs}" "${asset_dir}/inputs.json"
    )
  else
    cp "${inputs}" "${asset_dir}/inputs.json"
  fi
}

selected_workload="${MOBENCH_WORKLOAD:-all}"
case "${selected_workload}" in
  all | webauthn_assertion | passport_complete_age_check | passport_p1 | oprf_taceo | oprf_world_id_nullifier) ;;
  *)
    echo "error: unsupported MOBENCH_WORKLOAD ${selected_workload}" >&2
    exit 1
    ;;
esac

workloads=()
if [[ "${selected_workload}" == "all" || "${selected_workload}" == "webauthn_assertion" ]]; then
  copy_workload \
    webauthn_assertion \
    "${benchmark_root}/noir/webauthn_assertion/target/webauthn_assertion.json" \
    "${benchmark_root}/noir/webauthn_assertion/inputs.json"
  workloads+=(webauthn_assertion)
fi
if [[ "${selected_workload}" == "all" || "${selected_workload}" == "passport_p1" ]]; then
  copy_workload \
    passport_p1 \
    "${benchmark_root}/noir/passport_p1/target/passport_p1.json" \
    "${benchmark_root}/noir/passport_p1/Prover.toml"
  workloads+=(passport_p1)
fi
if [[ "${selected_workload}" == "all" || "${selected_workload}" == "passport_complete_age_check" ]]; then
  copy_workload \
    passport_complete_age_check \
    "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json" \
    "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml"
  workloads+=(passport_complete_age_check)
fi
if [[ "${selected_workload}" == "all" || "${selected_workload}" == "oprf_taceo" ]]; then
  copy_workload \
    oprf_taceo \
    "${repo_root}/target/v1-benchmarks/sources/oprf-nr/oprf_example/target/oprf_example.json" \
    "${repo_root}/target/v1-benchmarks/sources/oprf-nr/oprf_example/Prover.toml"
  workloads+=(oprf_taceo)
fi
if [[ "${selected_workload}" == "all" || "${selected_workload}" == "oprf_world_id_nullifier" ]]; then
  copy_workload \
    oprf_world_id_nullifier \
    "${repo_root}/noir-examples/oprf/target/oprf.json" \
    "${repo_root}/noir-examples/oprf/Prover.toml"
  workloads+=(oprf_world_id_nullifier)
fi

for workload in "${workloads[@]}"; do
  (
    cd "${barretenberg_root}"
    bun run generate-web-fixtures.ts "${dist}" "${workload}"
  )
done

echo "Built Barretenberg browser benchmark at ${dist}"
