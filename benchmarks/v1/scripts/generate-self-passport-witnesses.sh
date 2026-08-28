#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
circom_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/self"
witness_root="${V1_BENCHMARK_WITNESS_ROOT:-${repo_root}/target/v1-benchmarks/circom-witnesses}/self"
snarkjs="${repo_root}/target/v1-benchmarks/sources/self/node_modules/snarkjs/build/cli.cjs"

for command in bun cmp jq stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() {
    sha256sum "$1" | awk '{print $1}'
  }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
else
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi

stat_size() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

"${script_dir}/prepare-self-passport.sh"

generate_witnesses() {
  local name="$1"
  local fixture="$2"
  local circuit_dir="${circom_root}/${name}"
  local output_dir="${witness_root}/${name}"
  local wasm_witness="${output_dir}/wasm.wtns"
  local native_witness="${output_dir}/native.wtns"
  local wasm_generator="${circuit_dir}/${name}_js/generate_witness.js"
  local wasm="${circuit_dir}/${name}_js/${name}.wasm"
  local native_generator="${circuit_dir}/${name}_cpp/${name}"
  local r1cs="${circuit_dir}/${name}.r1cs"

  mkdir -p "${output_dir}"
  bun run "${wasm_generator}" "${wasm}" "${fixture}" "${wasm_witness}"
  "${native_generator}" "${fixture}" "${native_witness}"

  if ! cmp -s "${wasm_witness}" "${native_witness}"; then
    echo "error: ${name} WASM and native WTNS files differ" >&2
    exit 1
  fi

  # SnarkJS 0.7.5's web-worker shim is not compatible with Bun's EventTarget.
  # Keep this validation-only exception pinned to Self's required Node 22.
  node "${snarkjs}" wtns check "${r1cs}" "${wasm_witness}"

  jq -n \
    --arg workload "${name}" \
    --arg sha256 "$(hash_file "${wasm_witness}")" \
    --argjson size "$(stat_size "${wasm_witness}")" \
    '{
      schema_version: 1,
      workload: $workload,
      witness_format: "WTNS v2",
      generators: ["Circom WASM", "Circom portable C++"],
      byte_identical: true,
      size: $size,
      sha256: $sha256,
      constraints_checked: true
    }' >"${output_dir}/result.json"

  echo "verified ${name}: $(stat_size "${wasm_witness}") bytes, $(hash_file "${wasm_witness}")"
}

generate_witnesses \
  "register_sha256_sha256_sha256_rsa_65537_4096" \
  "${benchmark_root}/circom/fixtures/self/register_sha256_sha256_sha256_rsa_65537_4096.json"
generate_witnesses \
  "vc_and_disclose" \
  "${benchmark_root}/circom/fixtures/self/vc_and_disclose.json"

echo "Self passport WASM and portable C++ witness generators agree."
