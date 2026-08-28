#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
version="$(jq -r '.wasm_bindgen_cli.version' "${lock_file}")"
install_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}/wasm-bindgen-cli-${version}"
binary="${install_root}/bin/wasm-bindgen"

for command in cargo jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ -x "${binary}" ]]; then
  actual_version="$("${binary}" --version | awk '{print $2}')"
  if [[ "${actual_version}" != "${version}" ]]; then
    echo "error: ${binary} reports ${actual_version}, expected ${version}" >&2
    exit 1
  fi
  echo "${binary}"
  exit 0
fi

cargo install \
  --locked \
  --root "${install_root}" \
  --version "${version}" \
  wasm-bindgen-cli

"${binary}" --version >&2
echo "${binary}"
