#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/circom/trusted-setup.lock.json"
setup_root="${V1_BENCHMARK_SETUP_ROOT:-${repo_root}/target/v1-benchmarks/trusted-setup}"
power="${1:-20}"
selector="powersOfTau28_hez_final_${power}"
artifact="$(jq -ec --arg name "${selector}" '.artifacts[] | select(.name == $name)' "${lock_file}")" || {
  echo "error: no trusted setup artifact is pinned for power ${power}" >&2
  exit 1
}
name="$(jq -r '.name' <<<"${artifact}")"
url="$(jq -r '.url' <<<"${artifact}")"
expected_size="$(jq -r '.size' <<<"${artifact}")"
expected_sha256="$(jq -r '.sha256 // empty' <<<"${artifact}")"
expected_hash="$(jq -r '.blake2b512' <<<"${artifact}")"
destination="${setup_root}/${name}.ptau"

for command in curl jq openssl stat; do
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

verify() {
  local actual_size
  local actual_sha256
  local actual_hash
  actual_size="$(stat_size "${destination}")"
  if [[ "${actual_size}" != "${expected_size}" ]]; then
    return 1
  fi
  if [[ -n "${expected_sha256}" ]]; then
    actual_sha256="$(
      openssl dgst -sha256 "${destination}" |
        awk '{print tolower($NF)}'
    )"
    if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
      return 1
    fi
  fi
  actual_hash="$(
    openssl dgst -blake2b512 "${destination}" |
      awk '{print tolower($NF)}'
  )"
  [[ "${actual_hash}" == "${expected_hash}" ]]
}

if [[ -f "${destination}" ]] && verify; then
  echo "${destination}"
  exit 0
fi

mkdir -p "${setup_root}"
curl \
  --fail \
  --location \
  --retry 3 \
  --continue-at - \
  --output "${destination}" \
  "${url}"

if ! verify; then
  echo "error: downloaded PTAU does not match the pinned size and checksums" >&2
  exit 1
fi

echo "${destination}"
