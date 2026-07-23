#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <register_sha256_sha256_sha256_rsa_65537_4096|vc_and_disclose>" >&2
  exit 2
fi

name="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
groth16_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/self/${name}"
witness_root="${V1_BENCHMARK_WITNESS_ROOT:-${repo_root}/target/v1-benchmarks/circom-witnesses}/self/${name}"
output_root="${V1_BENCHMARK_MOBILE_FIXTURE_ROOT:-${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16}/${name}"

case "${name}" in
  register_sha256_sha256_sha256_rsa_65537_4096)
    cache_slug="passport-register"
    ;;
  vc_and_disclose)
    cache_slug="passport-disclose"
    ;;
  *)
    echo "error: unsupported Self circuit ${name}" >&2
    exit 1
    ;;
esac

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

size_file() {
  if stat -f '%z' "$1" >/dev/null 2>&1; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

zkey="${groth16_root}/${name}_0000.zkey"
verification_key="${groth16_root}/verification_key.json"
witness="${witness_root}/wasm.wtns"
input="${benchmark_root}/circom/fixtures/self/${name}.json"

if [[ "${V1_BENCHMARK_PREPARE_MISSING:-0}" == "1" ]]; then
  if [[ ! -f "${witness}" ]]; then
    "${script_dir}/generate-self-passport-witnesses.sh"
  fi
  if [[ ! -f "${zkey}" || ! -f "${verification_key}" ]]; then
    "${script_dir}/prepare-self-groth16.sh" "${name}"
  fi
fi

for required in "${zkey}" "${verification_key}" "${witness}" "${input}"; do
  if [[ ! -f "${required}" ]]; then
    echo "error: missing prepared artifact ${required}" >&2
    echo "rerun with V1_BENCHMARK_PREPARE_MISSING=1 to prepare missing artifacts" >&2
    exit 1
  fi
done

resources="${output_root}/resources"
mkdir -p "${resources}"

stage_file() {
  local source="$1"
  local destination="$2"
  local source_hash

  source_hash="$(hash_file "${source}")"
  if [[ -f "${destination}" ]] \
    && ! [[ "${source}" -ef "${destination}" ]] \
    && [[ "$(hash_file "${destination}")" == "${source_hash}" ]]; then
    return
  fi

  rm -f "${destination}"
  if cp -c "${source}" "${destination}" 2>/dev/null; then
    return
  fi
  if cp --reflink=auto "${source}" "${destination}" 2>/dev/null; then
    return
  fi
  rm -f "${destination}"
  cp "${source}" "${destination}"
}

stage_file "${zkey}" "${resources}/proving_key.zkey"
stage_file "${verification_key}" "${resources}/verification_key.json"
stage_file "${witness}" "${resources}/reference.wtns"
stage_file "${input}" "${resources}/input.json"

rows_file="$(mktemp "${TMPDIR:-/tmp}/provekit-v1-groth16-rows.XXXXXX")"
base_file="$(mktemp "${TMPDIR:-/tmp}/provekit-v1-groth16-base.XXXXXX")"
cleanup() {
  rm -f "${rows_file}" "${base_file}"
}
trap cleanup EXIT

add_artifact() {
  local logical_name="$1"
  local role="$2"
  local path="$3"
  local circuit_download="$4"
  local measured_phase="$5"

  jq -cn \
    --arg logical_name "${logical_name}" \
    --arg role "${role}" \
    --argjson bytes "$(size_file "${path}")" \
    --arg sha256 "$(hash_file "${path}")" \
    --argjson circuit_download "${circuit_download}" \
    --arg measured_phase "${measured_phase}" \
    '{
      logical_name: $logical_name,
      role: $role,
      bytes: $bytes,
      sha256: $sha256,
      circuit_download: $circuit_download,
      measured_phase: $measured_phase
    }' >>"${rows_file}"
}

add_artifact "proving_key.zkey" "groth16-proving-key" \
  "${resources}/proving_key.zkey" true "loaded-before-measurement"
add_artifact "verification_key.json" "groth16-verification-key" \
  "${resources}/verification_key.json" true "loaded-before-measurement"
add_artifact "reference.wtns" "proof-only-reference-witness" \
  "${resources}/reference.wtns" false "harness-input-not-timed"
add_artifact "input.json" "witness-generation-input" \
  "${resources}/input.json" false "harness-input-not-timed"

jq -S -n \
  --arg workload "${name}" \
  --arg cache_slug "${cache_slug}" \
  --slurpfile artifacts "${rows_file}" \
  '{
    schema_version: 1,
    backend: "circom-rapidsnark-groth16",
    workload: $workload,
    cache_slug: $cache_slug,
    preparation: {
      policy: "prepare-once-per-campaign",
      proving_key_is_campaign_specific: true
    },
    packaging: {
      one_workload_per_app: true,
      ios: {
        resource: "uncompressed installed app bundle file",
        access: "mmap Bundle.main resource directly; never copy to Documents or tmp"
      },
      android: {
        resource: "APK asset with zkey and wtns in androidResources.noCompress",
        access: "AssetManager.openFd plus mmap using the asset offset and length"
      }
    },
    timing_boundary: {
      integrity_check: "before measured iterations",
      resource_open_and_mmap: "setup phase",
      witness_generation: "separate benchmark function",
      proof_generation: "measured with prepared reference witness",
      verification: "separate benchmark function"
    },
    artifacts: $artifacts
  }' >"${base_file}"

campaign_hash="$(jq -S -c . "${base_file}" | hash_file /dev/stdin)"
manifest="${output_root}/fixture-manifest.json"
jq -S \
  --arg campaign_hash "${campaign_hash}" \
  --arg ios_custom_id "pkv1-g16-ios-${cache_slug}-${campaign_hash:0:16}" \
  --arg android_custom_id "pkv1-g16-android-${cache_slug}-${campaign_hash:0:16}" \
  '. + {
    campaign_hash: $campaign_hash,
    browserstack_fixture_id_prefixes: {
      ios: $ios_custom_id,
      android: $android_custom_id
    }
  }' "${base_file}" >"${manifest}"

echo "Prepared ${manifest}"
echo "Campaign hash: ${campaign_hash}"
