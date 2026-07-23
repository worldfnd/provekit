#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
lock_file="${benchmark_root}/circom/artifacts.lock.json"

for command in jq stat; do
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

jq -c '.artifacts[]' "${lock_file}" | while IFS= read -r artifact; do
  relative_path="$(jq -r '.source' <<<"${artifact}")"
  expected_size="$(jq -r '.size' <<<"${artifact}")"
  expected_sha="$(jq -r '.sha256' <<<"${artifact}")"
  path="${source_root}/${relative_path}"

  if [[ ! -f "${path}" ]]; then
    echo "error: missing pinned Circom artifact ${path}" >&2
    exit 1
  fi

  if [[ "$(uname -s)" == "Darwin" ]]; then
    actual_size="$(stat -f '%z' "${path}")"
  else
    actual_size="$(stat -c '%s' "${path}")"
  fi
  actual_sha="$(hash_file "${path}")"

  if [[ "${actual_size}" != "${expected_size}" ]]; then
    echo "error: ${relative_path} is ${actual_size} bytes, expected ${expected_size}" >&2
    exit 1
  fi
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "error: ${relative_path} has SHA-256 ${actual_sha}, expected ${expected_sha}" >&2
    exit 1
  fi

  echo "verified ${relative_path}"
done
