#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
groth16_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/passport_p1"
witness_root="${V1_BENCHMARK_WITNESS_ROOT:-${repo_root}/target/v1-benchmarks/circom-witnesses}/passport_p1"
self_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}/self"
snarkjs="${self_root}/node_modules/snarkjs/build/cli.cjs"

"${script_dir}/generate-passport-p1-witness.sh"
"${script_dir}/prepare-passport-p1-groth16.sh"

proof="${groth16_root}/proof.json"
public="${groth16_root}/public.json"
corrupted="${groth16_root}/proof.corrupted.json"
start="$(perl -MTime::HiRes=time -e 'print time')"
NODE_OPTIONS=--max-old-space-size=32768 \
  node "${snarkjs}" groth16 prove "${groth16_root}/passport_p1_final.zkey" \
  "${witness_root}/wasm.wtns" "${proof}" "${public}"
prove_seconds="$(perl -MTime::HiRes=time -e 'printf "%.6f", time - $ARGV[0]' "${start}")"
node "${snarkjs}" groth16 verify "${groth16_root}/verification_key.json" "${public}" "${proof}"
jq '.pi_a[0] = "1"' "${proof}" >"${corrupted}"
if node "${snarkjs}" groth16 verify "${groth16_root}/verification_key.json" "${public}" "${corrupted}" >/dev/null 2>&1; then
  echo "error: corrupted P1 proof was accepted" >&2
  exit 1
fi
jq -n --argjson prove_seconds "${prove_seconds}" \
  --arg proof_sha256 "$(shasum -a 256 "${proof}" | awk '{print $1}')" \
  --arg public_sha256 "$(shasum -a 256 "${public}" | awk '{print $1}')" \
  '{schema_version: 1, verified: true, corrupted_proof_rejected: true, prove_seconds: $prove_seconds, proof_sha256: $proof_sha256, public_sha256: $public_sha256}' \
  >"${groth16_root}/smoke.json"
cat "${groth16_root}/smoke.json"
