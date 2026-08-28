#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
circom_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/passport_p1"
witness_root="${V1_BENCHMARK_WITNESS_ROOT:-${repo_root}/target/v1-benchmarks/circom-witnesses}/passport_p1"
self_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}/self"
fixture="${benchmark_root}/circom/fixtures/passport_p1/input.json"
snarkjs="${self_root}/node_modules/snarkjs/build/cli.cjs"

for command in bun cmp jq node stat; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

hash_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}
stat_size() {
  if [[ "$(uname -s)" == Darwin ]]; then stat -f '%z' "$1"; else stat -c '%s' "$1"; fi
}

"${script_dir}/prepare-passport-p1-circom.sh"
mkdir -p "${witness_root}"
wasm_witness="${witness_root}/wasm.wtns"
native_witness="${witness_root}/native.wtns"
node "${circom_root}/passport_p1_js/generate_witness.js" \
  "${circom_root}/passport_p1_js/passport_p1.wasm" "${fixture}" "${wasm_witness}"
"${circom_root}/passport_p1_cpp/passport_p1" "${fixture}" "${native_witness}"
cmp -s "${wasm_witness}" "${native_witness}" || {
  echo "error: P1 WASM and portable C++ WTNS files differ" >&2
  exit 1
}
node "${snarkjs}" wtns check "${circom_root}/passport_p1.r1cs" "${wasm_witness}"

jq -n \
  --arg workload passport_p1 \
  --arg sha256 "$(hash_file "${wasm_witness}")" \
  --argjson size "$(stat_size "${wasm_witness}")" \
  '{schema_version: 1, workload: $workload, witness_format: "WTNS v2", generators: ["Circom WASM", "Circom portable C++"], byte_identical: true, constraints_checked: true, size: $size, sha256: $sha256}' \
  >"${witness_root}/result.json"
echo "verified P1 witness: $(stat_size "${wasm_witness}") bytes, $(hash_file "${wasm_witness}")"
