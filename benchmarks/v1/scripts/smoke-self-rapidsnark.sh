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
rapidsnark="${repo_root}/target/v1-benchmarks/sources/rapidsnark"
groth16_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/self/${name}"
witness="${repo_root}/target/v1-benchmarks/circom-witnesses/self/${name}/wasm.wtns"
zkey="${groth16_root}/${name}_0000.zkey"
verification_key="${groth16_root}/verification_key.json"
proof="${groth16_root}/proof.json"
public_inputs="${groth16_root}/public.json"
corrupted_proof="${groth16_root}/proof.corrupted.json"
result="${groth16_root}/rapidsnark-smoke.json"

case "$(uname -m)-$(uname -s)" in
  arm64-Darwin)
    prover_package="package_macos_arm64"
    ;;
  x86_64-Darwin | x86_64-Linux)
    prover_package="package"
    ;;
  aarch64-Linux | arm64-Linux)
    prover_package="package_arm64"
    ;;
  *)
    echo "error: unsupported Rapidsnark host $(uname -m)-$(uname -s)" >&2
    exit 1
    ;;
esac

prover="${rapidsnark}/${prover_package}/bin/prover"
verifier="${rapidsnark}/${prover_package}/bin/verifier"

for command in jq perl stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

stat_size() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

"${script_dir}/build-rapidsnark-host.sh"
if [[ ! -f "${witness}" ]]; then
  "${script_dir}/generate-self-passport-witnesses.sh"
fi
"${script_dir}/prepare-self-groth16.sh" "${name}"

prover_time="${groth16_root}/prover.time"
verify_time="${groth16_root}/verifier.time"
start="$(perl -MTime::HiRes=time -e 'print time')"
/usr/bin/time -l "${prover}" \
  "${zkey}" \
  "${witness}" \
  "${proof}" \
  "${public_inputs}" \
  2>"${prover_time}"
prove_seconds="$(
  perl -MTime::HiRes=time -e \
    'printf "%.6f", time - $ARGV[0]' \
    "${start}"
)"

start="$(perl -MTime::HiRes=time -e 'print time')"
/usr/bin/time -l "${verifier}" \
  "${verification_key}" \
  "${public_inputs}" \
  "${proof}" \
  2>"${verify_time}"
verify_seconds="$(
  perl -MTime::HiRes=time -e \
    'printf "%.6f", time - $ARGV[0]' \
    "${start}"
)"

jq '.pi_a[0] = "1"' "${proof}" >"${corrupted_proof}"
if "${verifier}" \
  "${verification_key}" \
  "${public_inputs}" \
  "${corrupted_proof}" >/dev/null 2>&1; then
  echo "error: Rapidsnark accepted a corrupted ${name} proof" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  prove_max_rss="$(awk '/maximum resident set size/ { print $1 }' "${prover_time}")"
  verify_max_rss="$(awk '/maximum resident set size/ { print $1 }' "${verify_time}")"
else
  prove_max_rss=0
  verify_max_rss=0
fi

jq -n \
  --arg workload "${name}" \
  --argjson proof_size "$(stat_size "${proof}")" \
  --argjson public_input_size "$(stat_size "${public_inputs}")" \
  --argjson prove_seconds "${prove_seconds}" \
  --argjson verify_seconds "${verify_seconds}" \
  --argjson prove_max_rss_bytes "${prove_max_rss:-0}" \
  --argjson verify_max_rss_bytes "${verify_max_rss:-0}" \
  '{
    schema_version: 1,
    workload: $workload,
    backend: "rapidsnark-groth16",
    proof_size: $proof_size,
    public_input_size: $public_input_size,
    prove_seconds: $prove_seconds,
    verify_seconds: $verify_seconds,
    prove_max_rss_bytes: $prove_max_rss_bytes,
    verify_max_rss_bytes: $verify_max_rss_bytes,
    verified: true,
    corrupted_proof_rejected: true
  }' >"${result}"

cat "${result}"
