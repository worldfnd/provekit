#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"

for command in curl jq tar; do
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

case "$(uname -m)-$(uname -s)" in
  arm64-Darwin)
    platform="aarch64-apple-darwin"
    ;;
  x86_64-Darwin)
    platform="x86_64-apple-darwin"
    ;;
  aarch64-Linux | arm64-Linux)
    platform="aarch64-unknown-linux-gnu"
    ;;
  x86_64-Linux)
    platform="x86_64-unknown-linux-gnu"
    ;;
  *)
    echo "error: unsupported Nargo host $(uname -m)-$(uname -s)" >&2
    exit 1
    ;;
esac

version="$(jq -r '.noir.version' "${lock_file}")"
base_url="$(jq -r '.noir.base_url' "${lock_file}")"
asset="$(jq -r --arg platform "${platform}" '.noir.assets[$platform].name' "${lock_file}")"
expected_sha="$(jq -r --arg platform "${platform}" '.noir.assets[$platform].sha256' "${lock_file}")"
destination="${tool_root}/nargo-${version}-${platform}"

if [[ -x "${destination}/nargo" ]]; then
  actual_version="$("${destination}/nargo" --version | sed -n 's/^nargo version = //p')"
  if [[ "${actual_version}" != "${version}" ]]; then
    echo "error: ${destination}/nargo reports ${actual_version}, expected ${version}" >&2
    exit 1
  fi
  echo "${destination}/nargo"
  exit 0
fi

mkdir -p "${tool_root}"
archive="$(mktemp "${tool_root}/nargo.XXXXXX.tar.gz")"
extract_dir="$(mktemp -d "${tool_root}/nargo.XXXXXX")"
trap 'rm -f "${archive}"; rm -rf "${extract_dir}"' EXIT

curl --fail --location --silent --show-error "${base_url}/${asset}" --output "${archive}"
actual_sha="$(hash_file "${archive}")"
if [[ "${actual_sha}" != "${expected_sha}" ]]; then
  echo "error: ${asset} has SHA-256 ${actual_sha}, expected ${expected_sha}" >&2
  exit 1
fi

tar -xzf "${archive}" -C "${extract_dir}"
if [[ ! -x "${extract_dir}/nargo" ]]; then
  echo "error: ${asset} did not contain an executable nargo" >&2
  exit 1
fi

mv "${extract_dir}" "${destination}"
trap 'rm -f "${archive}"' EXIT
"${destination}/nargo" --version >&2
echo "${destination}/nargo"
