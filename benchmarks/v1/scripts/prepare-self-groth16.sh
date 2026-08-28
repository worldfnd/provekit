#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <register_sha256_sha256_sha256_rsa_65537_4096|vc_and_disclose>" >&2
  exit 1
fi

name="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
circom_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/self"
output_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/self/${name}"
snarkjs="${repo_root}/target/v1-benchmarks/sources/self/node_modules/snarkjs/build/cli.cjs"
r1cs="${circom_root}/${name}/${name}.r1cs"
zkey="${output_root}/${name}_0000.zkey"
verification_key="${output_root}/verification_key.json"

case "${name}" in
  register_sha256_sha256_sha256_rsa_65537_4096 | vc_and_disclose) ;;
  *)
    echo "error: unsupported Self circuit ${name}" >&2
    exit 1
    ;;
esac

for command in node; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/prepare-self-passport.sh"
ptau="$("${script_dir}/bootstrap-ptau.sh")"
mkdir -p "${output_root}"

if [[ ! -f "${zkey}" ]]; then
  node "${snarkjs}" groth16 setup "${r1cs}" "${ptau}" "${zkey}"
fi
node "${snarkjs}" zkey export verificationkey "${zkey}" "${verification_key}"
node "${snarkjs}" zkey verify "${r1cs}" "${ptau}" "${zkey}"

echo "Prepared and verified ${zkey}"
