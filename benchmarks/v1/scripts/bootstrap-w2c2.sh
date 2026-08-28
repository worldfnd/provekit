#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"
source_dir="${source_root}/w2c2"
build_dir="${repo_root}/target/v1-benchmarks/build/w2c2-host"
binary="${tool_root}/w2c2/bin/w2c2"

for command in cmake git jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/bootstrap-sources.sh" >/dev/null
expected_revision="$(
  jq -er '.sources[] | select(.name == "w2c2") | .revision' \
    "${benchmark_root}/sources.lock.json"
)"
if [[ "$(git -C "${source_dir}" rev-parse HEAD)" != "${expected_revision}" ]]; then
  echo "error: w2c2 source revision does not match sources.lock.json" >&2
  exit 1
fi

if [[ ! -x "${binary}" ]]; then
  cmake \
    -S "${source_dir}" \
    -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build "${build_dir}" --target w2c2 --parallel "${V1_BUILD_JOBS:-4}"
  mkdir -p "$(dirname "${binary}")"
  install -m 0755 "${build_dir}/w2c2/w2c2" "${binary}"
fi

echo "${binary}"
