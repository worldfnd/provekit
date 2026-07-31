#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
output="${V1_NOIR_SRS_PATH:-${repo_root}/target/v1-benchmarks/noir-srs/noir_beta19_campaign.dat}"

for command in curl jq openssl stat; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

url="$(jq -er '.native_noir.srs.url' "${lock_file}")"
bytes="$(jq -er '.native_noir.srs.bytes' "${lock_file}")"
sha256="$(jq -er '.native_noir.srs.sha256' "${lock_file}")"
range_end="$((bytes - 1))"

mkdir -p "$(dirname "${output}")"
if [[ -f "${output}" ]]; then
  actual_bytes="$(stat -f '%z' "${output}")"
  actual_sha="$(openssl dgst -sha256 "${output}" | awk '{print tolower($NF)}')"
  if [[ "${actual_bytes}" == "${bytes}" && "${actual_sha}" == "${sha256}" ]]; then
    echo "${output}"
    exit 0
  fi
  echo "error: existing Noir SRS does not match the locked size/hash: ${output}" >&2
  exit 1
fi

partial="${output}.partial"
curl \
  --fail \
  --location \
  --retry 3 \
  --retry-all-errors \
  --connect-timeout 20 \
  --max-time 1200 \
  --range "0-${range_end}" \
  --output "${partial}" \
  "${url}"

actual_bytes="$(stat -f '%z' "${partial}")"
actual_sha="$(openssl dgst -sha256 "${partial}" | awk '{print tolower($NF)}')"
[[ "${actual_bytes}" == "${bytes}" ]] || {
  echo "error: Noir SRS size mismatch: expected ${bytes}, got ${actual_bytes}" >&2
  exit 1
}
[[ "${actual_sha}" == "${sha256}" ]] || {
  echo "error: Noir SRS hash mismatch: expected ${sha256}, got ${actual_sha}" >&2
  exit 1
}
mv "${partial}" "${output}"
echo "${output}"
