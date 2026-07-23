#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_dir="${repo_root}/target/v1-benchmarks/sources/circom"
install_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}/circom"
binary="${install_root}/bin/circom"

for command in cargo jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/bootstrap-sources.sh" >/dev/null

if [[ -x "${binary}" ]]; then
  "${binary}" --version >&2
  echo "${binary}"
  exit 0
fi

cargo install --locked --path "${source_dir}/circom" --root "${install_root}"
"${binary}" --version >&2
echo "${binary}"
