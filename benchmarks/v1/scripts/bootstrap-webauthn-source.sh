#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/sources.lock.json"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
nargo_home="${V1_BENCHMARK_NARGO_HOME:-${repo_root}/target/v1-benchmarks/nargo-home}"
destination="${source_root}/world-id-protocol"
vendor_relative="crates/proof/noir/passkey-ownership-proof/vendor"
required_manifests=(
  "webauthn/Nargo.toml"
  "noir-bignum-mavros/Nargo.toml"
  "noir_bigcurve-mavros/Nargo.toml"
  "nodash/Nargo.toml"
)

for command in git jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

source_entry="$(jq -ce '.sources[] | select(.name == "world-id-protocol")' "${lock_file}")"
url="$(jq -r '.url' <<<"${source_entry}")"
revision="$(jq -r '.revision' <<<"${source_entry}")"

validate_checkout() {
  local checkout="$1"
  local actual_revision

  actual_revision="$(git -C "${checkout}" rev-parse HEAD)"
  if [[ "${actual_revision}" != "${revision}" ]]; then
    echo "error: ${checkout} is at ${actual_revision}, expected ${revision}" >&2
    return 1
  fi

  for manifest in "${required_manifests[@]}"; do
    if [[ ! -s "${checkout}/${vendor_relative}/${manifest}" ]]; then
      echo "error: pinned WebAuthn dependency is missing ${vendor_relative}/${manifest}" >&2
      return 1
    fi
  done

  if [[ -n "$(git -C "${checkout}" status --porcelain -- "${vendor_relative}")" ]]; then
    echo "error: pinned World ID WebAuthn vendor source has local changes" >&2
    git -C "${checkout}" status --short -- "${vendor_relative}" >&2
    return 1
  fi
}

if [[ -e "${destination}" ]]; then
  if [[ ! -d "${destination}/.git" ]]; then
    echo "error: refusing to replace non-Git path ${destination}" >&2
    exit 1
  fi

  if [[ "$(git -C "${destination}" rev-parse HEAD)" != "${revision}" ]]; then
    echo "error: ${destination} is not at expected revision ${revision}" >&2
    echo "Remove or move that checkout explicitly before retrying." >&2
    exit 1
  fi

  missing_vendor_manifest=0
  for manifest in "${required_manifests[@]}"; do
    if [[ ! -s "${destination}/${vendor_relative}/${manifest}" ]]; then
      missing_vendor_manifest=1
      break
    fi
  done

  if [[ "${missing_vendor_manifest}" == "1" ]]; then
    if [[ "$(git -C "${destination}" config --bool core.sparseCheckout || true)" != "true" ]]; then
      echo "error: full checkout ${destination} is missing the pinned WebAuthn vendor source" >&2
      exit 1
    fi
    git -C "${destination}" sparse-checkout add "${vendor_relative}"
  fi
else
  mkdir -p "${source_root}"
  staging="$(mktemp -d "${source_root}/.world-id-protocol.XXXXXX")"
  cleanup_staging() {
    if [[ -n "${staging:-}" && -d "${staging}" ]]; then
      rm -rf -- "${staging}"
    fi
  }
  trap cleanup_staging EXIT

  echo "fetching the pinned World ID WebAuthn vendor source at ${revision}"
  git init --quiet "${staging}"
  git -C "${staging}" remote add origin "${url}"
  git -C "${staging}" sparse-checkout init --cone
  git -C "${staging}" sparse-checkout set "${vendor_relative}"
  git -C "${staging}" fetch --quiet --depth 1 --filter=blob:none origin "${revision}"
  git -C "${staging}" checkout --quiet --detach FETCH_HEAD
  validate_checkout "${staging}"
  mv "${staging}" "${destination}"
  staging=""
  trap - EXIT
fi

validate_checkout "${destination}"

ensure_nargo_git_dependency() {
  local source_name="$1"
  local repository_name="$2"
  local entry url dependency_revision dependency_tag dependency_destination staging_dependency
  entry="$(jq -ce --arg name "${source_name}" '.sources[] | select(.name == $name)' "${lock_file}")"
  url="$(jq -r '.url' <<<"${entry}")"
  dependency_revision="$(jq -r '.revision' <<<"${entry}")"
  dependency_tag="$(jq -r '.tag' <<<"${entry}")"
  dependency_destination="${nargo_home}/nargo/github.com/noir-lang/${repository_name}/${dependency_tag}"

  if [[ -e "${dependency_destination}" ]]; then
    if [[ ! -d "${dependency_destination}/.git" ]]; then
      echo "error: refusing to replace non-Git Nargo cache path ${dependency_destination}" >&2
      return 1
    fi
    if [[ "$(git -C "${dependency_destination}" rev-parse HEAD)" != "${dependency_revision}" ]] ||
      [[ -n "$(git -C "${dependency_destination}" status --porcelain)" ]]; then
      echo "error: cached ${source_name} does not match locked revision ${dependency_revision}" >&2
      return 1
    fi
    return
  fi

  mkdir -p "$(dirname "${dependency_destination}")"
  staging_dependency="$(mktemp -d "$(dirname "${dependency_destination}")/.${source_name}.XXXXXX")"
  echo "fetching pinned ${source_name} at ${dependency_revision}"
  git init --quiet "${staging_dependency}"
  git -C "${staging_dependency}" remote add origin "${url}"
  git -C "${staging_dependency}" fetch --quiet --depth 1 --filter=blob:none origin "${dependency_revision}"
  git -C "${staging_dependency}" checkout --quiet --detach FETCH_HEAD
  if [[ "$(git -C "${staging_dependency}" rev-parse HEAD)" != "${dependency_revision}" ]] ||
    [[ -n "$(git -C "${staging_dependency}" status --porcelain)" ]]; then
    echo "error: fetched ${source_name} does not match locked revision ${dependency_revision}" >&2
    return 1
  fi
  mv "${staging_dependency}" "${dependency_destination}"
}

ensure_nargo_git_dependency "noir-base64" "noir_base64"
ensure_nargo_git_dependency "noir-poseidon" "poseidon"
ensure_nargo_git_dependency "noir-sha256" "sha256"

echo "Pinned World ID WebAuthn source and Noir dependencies are ready"
