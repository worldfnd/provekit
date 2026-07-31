#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
install_root="${repo_root}/target/v1-benchmarks/toolchains/mobench"
revision_file="${install_root}/.source-revision"

repository="$(jq -er '.mobench.repository' "${lock_file}")"
revision="$(jq -er '.mobench.source_revision' "${lock_file}")"

if [[ -x "${install_root}/bin/cargo-mobench" ]] &&
  [[ -f "${revision_file}" ]] &&
  [[ "$(<"${revision_file}")" == "${revision}" ]]; then
  "${install_root}/bin/cargo-mobench" --version
  exit 0
fi

cargo install mobench \
  --git "${repository}" \
  --rev "${revision}" \
  --locked \
  --force \
  --root "${install_root}"

printf '%s\n' "${revision}" >"${revision_file}"
"${install_root}/bin/cargo-mobench" --version
