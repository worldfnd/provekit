#!/usr/bin/env bash

set -euo pipefail

version="${BARRETENBERG_VERSION:-0.87.0}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
install_dir="${repo_root}/target/v1-benchmarks/tools/barretenberg-${version}"
archive="${install_dir}/barretenberg-arm64-darwin.tar.gz"
binary="${install_dir}/bb"

if [[ "$(uname -s)-$(uname -m)" != "Darwin-arm64" ]]; then
  echo "error: the pinned Mac benchmark currently supports Darwin arm64 only" >&2
  exit 1
fi

if [[ ! -x "${binary}" ]]; then
  mkdir -p "${install_dir}"
  if [[ ! -f "${archive}" ]]; then
    gh release download "v${version}" \
      --repo AztecProtocol/aztec-packages \
      --pattern barretenberg-arm64-darwin.tar.gz \
      --dir "${install_dir}"
  fi
  tar -xzf "${archive}" -C "${install_dir}"
fi

actual="$("${binary}" --version)"
if [[ "${actual}" != "v${version}" ]]; then
  echo "error: expected Barretenberg v${version}, got ${actual}" >&2
  exit 1
fi

printf '%s\n' "${binary}"
