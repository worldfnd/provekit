#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wasm_root="$(cd "${script_dir}/.." && pwd)"
benchmark_root="$(cd "${wasm_root}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
dist_dir="${wasm_root}/dist"

for command in bun; do
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
(
  cd "${wasm_root}"
  bun install --frozen-lockfile
)

if [[ "${dist_dir}" != "${repo_root}/benchmarks/v1/wasm/dist" ]]; then
  echo "error: refusing to clean unexpected dist path ${dist_dir}" >&2
  exit 1
fi
rm -rf "${dist_dir}"
mkdir -p "${dist_dir}/assets"
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
    "${repo_root}/target/v1-benchmarks/sources/oprf-nr-v2/oprf_example/Prover.toml" \
    "${dist_dir}/assets/oprf_taceo/inputs.json"
)
(
  cd "${wasm_root}"
  bunx vite build
)

runtime_manifest="${repo_root}/target/v1-benchmarks/provekit-sdk-browser-files.tsv"
mkdir -p "$(dirname "${runtime_manifest}")"
{
  printf '# scope\tkind\tpath\tmime_type\n'
  printf 'shared-runtime\thtml\t%s\ttext/html; charset=utf-8\n' \
    "${dist_dir}/index.html"
  while IFS= read -r file; do
    case "${file}" in
      *.wasm) mime='application/wasm' ;;
      *.js) mime='text/javascript; charset=utf-8' ;;
      *) continue ;;
    esac
    printf 'shared-runtime\tpackage-runtime\t%s\t%s\n' "${file}" "${mime}"
  done < <(find "${dist_dir}" -maxdepth 2 -type f | LC_ALL=C sort)
  for workload in webauthn_assertion passport_complete_age_check oprf_taceo; do
    while IFS= read -r file; do
      printf '%s\tworkload-asset\t%s\tapplication/octet-stream\n' \
        "${workload}" "${file}"
    done < <(find "${dist_dir}/assets/${workload}" -type f | LC_ALL=C sort)
  done
} >"${runtime_manifest}"

(
  cd "${repo_root}"
  "${benchmark_root}/scripts/measure-bundle.sh" \
    "${runtime_manifest}" \
    "${dist_dir}/manifest.json"
)

echo "Built single-thread browser benchmark at ${dist_dir}"
