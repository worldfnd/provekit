#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/sources.lock.json"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"

for command in git jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

mkdir -p "${source_root}"

jq -c '.sources[]' "${lock_file}" | while IFS= read -r source; do
  name="$(jq -r '.name' <<<"${source}")"
  url="$(jq -r '.url' <<<"${source}")"
  revision="$(jq -r '.revision' <<<"${source}")"
  destination="${source_root}/${name}"

  if [[ -e "${destination}" ]]; then
    if [[ ! -d "${destination}/.git" ]]; then
      echo "error: refusing to replace non-Git path ${destination}" >&2
      exit 1
    fi

    actual_revision="$(git -C "${destination}" rev-parse HEAD)"
    if [[ "${actual_revision}" != "${revision}" ]]; then
      echo "error: ${destination} is at ${actual_revision}, expected ${revision}" >&2
      echo "Remove or move that checkout explicitly before retrying." >&2
      exit 1
    fi

    if [[ "$(jq '.sparse_paths | length' <<<"${source}")" -gt 0 ]]; then
      git -C "${destination}" sparse-checkout init --cone
      jq -r '.sparse_paths[]' <<<"${source}" |
        git -C "${destination}" sparse-checkout set --stdin
    elif git -C "${destination}" config --bool core.sparseCheckout | grep -qx true; then
      git -C "${destination}" sparse-checkout disable
    fi

    if [[ "$(jq -r '.submodules // false' <<<"${source}")" == "true" ]]; then
      git -C "${destination}" submodule update --init --recursive
    fi

    echo "verified ${name} at ${revision}"
    continue
  fi

  echo "fetching ${name} at ${revision}"
  git init --quiet "${destination}"
  git -C "${destination}" remote add origin "${url}"

  if [[ "$(jq '.sparse_paths | length' <<<"${source}")" -gt 0 ]]; then
    git -C "${destination}" sparse-checkout init --cone
    jq -r '.sparse_paths[]' <<<"${source}" |
      git -C "${destination}" sparse-checkout set --stdin
  fi

  git -C "${destination}" fetch --quiet --depth 1 origin "${revision}"
  git -C "${destination}" checkout --quiet --detach FETCH_HEAD

  actual_revision="$(git -C "${destination}" rev-parse HEAD)"
  if [[ "${actual_revision}" != "${revision}" ]]; then
    echo "error: fetched ${name} at ${actual_revision}, expected ${revision}" >&2
    exit 1
  fi

  if [[ "$(jq -r '.submodules // false' <<<"${source}")" == "true" ]]; then
    git -C "${destination}" submodule update --init --recursive
  fi

  echo "ready ${name}"
done

echo "Pinned sources are ready under ${source_root}"
