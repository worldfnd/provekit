#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
asset_root="${benchmark_root}/circom/web/dist/assets"
snarkjs="${benchmark_root}/circom/web/node_modules/snarkjs/build/cli.cjs"
lock_file="${benchmark_root}/toolchains.lock.json"
output_root="${repo_root}/target/v1-benchmarks/circom"

for command in jq node shasum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
[[ -f "${snarkjs}" ]] || {
  echo "error: install the locked Circom browser dependencies first" >&2
  exit 1
}

prepare_witness() {
  local group="$1"
  local name="$2"
  local output_name="$3"
  local assets="${asset_root}/${group}"
  local output="${output_root}/${group}/${output_name}.wtns"
  local proof="${output_root}/${group}/${output_name}.proof.json"
  local public="${output_root}/${group}/${output_name}.public.json"
  local expected
  expected="$(
    jq -er \
      --arg name "${output_name}" \
      '.circom_native_frozen_witnesses[$name].sha256' \
      "${lock_file}"
  )"

  mkdir -p "$(dirname "${output}")"
  if [[ ! -f "${output}" ]]; then
    NODE_OPTIONS=--max-old-space-size=32768 \
      node "${snarkjs}" wtns calculate \
      "${assets}/${name}.wasm" \
      "${assets}/${name}.input.json" \
      "${output}"
  fi
  actual="$(shasum -a 256 "${output}" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || {
    echo "error: frozen witness drift for ${output_name}" >&2
    echo "expected ${expected}, got ${actual}" >&2
    exit 1
  }

  NODE_OPTIONS=--max-old-space-size=32768 \
    node "${snarkjs}" groth16 prove \
    "${assets}/${name}.zkey" \
    "${output}" \
    "${proof}" \
    "${public}"
  node "${snarkjs}" groth16 verify \
    "${assets}/${name}.vkey.json" \
    "${public}" \
    "${proof}"
}

prepare_witness oprf oprf_query oprf_query
prepare_witness oprf oprf_nullifier oprf_nullifier
prepare_witness passport vc_and_disclose vc_and_disclose
prepare_witness \
  passport \
  register_sha256_sha256_sha256_rsa_65537_4096 \
  register_sha256_sha256_sha256_rsa_65537_4096
prepare_witness webauthn webauthn_default fixture
