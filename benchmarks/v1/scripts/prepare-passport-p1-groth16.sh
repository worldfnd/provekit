#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
circom_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/passport_p1"
output_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/passport_p1"
self_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}/self"
snarkjs="${self_root}/node_modules/snarkjs/build/cli.cjs"
r1cs="${circom_root}/passport_p1.r1cs"
phase0_zkey="${output_root}/passport_p1_0000.zkey"
zkey="${output_root}/passport_p1_final.zkey"
verification_key="${output_root}/verification_key.json"
ceremony="${output_root}/ceremony.json"

for command in node awk; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/prepare-passport-p1-circom.sh"
ptau="$("${script_dir}/bootstrap-ptau.sh" 20)"
constraints="$(node "${snarkjs}" r1cs info "${r1cs}" | awk '/Constraints:/ {print $NF}')"
[[ -n "${constraints}" && "${constraints}" -le 1048576 ]] || {
  echo "error: P1 has ${constraints:-unknown} constraints, exceeding power-20 PTAU capacity" >&2
  exit 1
}

mkdir -p "${output_root}"
if [[ ! -f "${phase0_zkey}" ]]; then
  NODE_OPTIONS=--max-old-space-size=32768 \
    node "${snarkjs}" groth16 setup "${r1cs}" "${ptau}" "${phase0_zkey}"
fi
if [[ ! -f "${zkey}" ]]; then
  # This public deterministic beacon is reproducible benchmark entropy, not a
  # production ceremony contribution. The final key is deliberately marked as
  # such. zkey beacon avoids the interactive entropy prompt in SnarkJS 0.7.6.
  NODE_OPTIONS=--max-old-space-size=32768 \
    node "${snarkjs}" zkey beacon \
      "${phase0_zkey}" "${zkey}" \
      "8e39a496f744a6bfb75cbe3e9745a128382ed94421efc0dd1d4db6bdad52c5f9" \
      10
fi
node "${snarkjs}" zkey export verificationkey "${zkey}" "${verification_key}"
node "${snarkjs}" zkey verify "${r1cs}" "${ptau}" "${zkey}"
jq -n \
  --arg phase0_sha256 "$(shasum -a 256 "${phase0_zkey}" | awk '{print $1}')" \
  --arg final_sha256 "$(shasum -a 256 "${zkey}" | awk '{print $1}')" \
  --argjson constraints "${constraints}" \
  '{schema_version: 1, ceremony: "deterministic-benchmark-only", production_safe: false, phase2_contribution: true, entropy: "public deterministic benchmark beacon; not suitable for production", constraints: $constraints, phase0_zkey_sha256: $phase0_sha256, final_zkey_sha256: $final_sha256}' \
  >"${ceremony}"
echo "prepared non-production P1 Groth16 final zkey with ${constraints} constraints"
