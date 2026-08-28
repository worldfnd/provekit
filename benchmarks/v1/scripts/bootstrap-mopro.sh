#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"
install_root="${tool_root}/mopro"
binary="${install_root}/bin/mopro"
lock_file="${benchmark_root}/sources.lock.json"

for command in cargo git jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/bootstrap-sources.sh" >/dev/null

mopro_revision="$(
  jq -er '.sources[] | select(.name == "mopro") | .revision' "${lock_file}"
)"
mopro_version="$(
  jq -er '.sources[] | select(.name == "mopro") | .version' "${lock_file}"
)"
rapidsnark_revision="$(
  jq -er '.sources[] | select(.name == "rust-rapidsnark") | .revision' "${lock_file}"
)"

if [[ "$(git -C "${source_root}/mopro" rev-parse HEAD)" != "${mopro_revision}" ]]; then
  echo "error: Mopro checkout does not match sources.lock.json" >&2
  exit 1
fi
if [[ "$(git -C "${source_root}/rust-rapidsnark" rev-parse HEAD)" != "${rapidsnark_revision}" ]]; then
  echo "error: rust-rapidsnark checkout does not match sources.lock.json" >&2
  exit 1
fi

if [[ ! -x "${binary}" ]]; then
  cargo install \
    --locked \
    --path "${source_root}/mopro/cli" \
    --root "${install_root}"
fi

actual_version="$("${binary}" --version | awk '{print $2}')"
if [[ "${actual_version}" != "${mopro_version}" ]]; then
  echo "error: ${binary} reports ${actual_version}, expected ${mopro_version}" >&2
  exit 1
fi

echo "${binary}"
