#!/usr/bin/env bash

set -euo pipefail

build_ios=false
build_android=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
  --build-ios)
    build_ios=true
    ;;
  --build-android)
    build_android=true
    ;;
  -h | --help)
    echo "usage: prepare-mopro-native-adapters.sh [--build-ios] [--build-android]"
    exit 0
    ;;
  *)
    echo "error: unknown argument $1" >&2
    exit 1
    ;;
  esac
  shift
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
project_root="${V1_MOPRO_PROJECT_ROOT:-${repo_root}/target/v1-benchmarks/mopro/provekit-v1-mobile-adapters}"
artifact_root="${V1_WEBAUTHN_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom/webauthn}"

for command in bun cargo cp mkdir; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/prepare-webauthn-circom.sh"
"${script_dir}/compile-noir-workloads.sh"
"${script_dir}/prepare-noir-beta19-srs.sh" >/dev/null
mopro="$("${script_dir}/bootstrap-mopro.sh")"
w2c2="$("${script_dir}/bootstrap-w2c2.sh")"
nargo="$("${script_dir}/bootstrap-nargo.sh")"

if [[ ! -d "${project_root}" ]]; then
  mkdir -p "$(dirname "${project_root}")"
  (
    cd "$(dirname "${project_root}")"
    "${mopro}" init \
      --adapter circom,noir \
      --project-name "$(basename "${project_root}")"
  )
fi

noir_vectors="${project_root}/test-vectors/noir/campaign"
mkdir -p \
  "${noir_vectors}/webauthn" \
  "${noir_vectors}/passport" \
  "${noir_vectors}/passport_p1" \
  "${noir_vectors}/oprf"
(
  cd "${benchmark_root}/noir/webauthn_assertion"
  "${nargo}" execute campaign_webauthn --skip-brillig-constraints-check
)
(
  cd "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check"
  "${nargo}" execute campaign_passport --skip-brillig-constraints-check
)
(
  cd "${benchmark_root}/noir/passport_p1"
  "${nargo}" execute campaign_passport_p1 --skip-brillig-constraints-check
)
(
  cd "${repo_root}/noir-examples/oprf"
  "${nargo}" execute campaign_oprf --skip-brillig-constraints-check
)
cp \
  "${benchmark_root}/noir/webauthn_assertion/target/webauthn_assertion.json" \
  "${noir_vectors}/webauthn/circuit.json"
cp \
  "${benchmark_root}/noir/webauthn_assertion/target/campaign_webauthn.gz" \
  "${noir_vectors}/webauthn/witness.gz"
cp "${benchmark_root}/noir/webauthn_assertion/Prover.toml" \
  "${noir_vectors}/webauthn/Prover.toml"
cp \
  "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json" \
  "${noir_vectors}/passport/circuit.json"
cp \
  "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/target/campaign_passport.gz" \
  "${noir_vectors}/passport/witness.gz"
cp "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml" \
  "${noir_vectors}/passport/Prover.toml"
cp \
  "${benchmark_root}/noir/passport_p1/target/passport_p1.json" \
  "${noir_vectors}/passport_p1/circuit.json"
cp \
  "${benchmark_root}/noir/passport_p1/target/campaign_passport_p1.gz" \
  "${noir_vectors}/passport_p1/witness.gz"
cp "${benchmark_root}/noir/passport_p1/Prover.toml" \
  "${noir_vectors}/passport_p1/Prover.toml"
cp \
  "${repo_root}/noir-examples/oprf/target/oprf.json" \
  "${noir_vectors}/oprf/circuit.json"
cp \
  "${repo_root}/noir-examples/oprf/target/campaign_oprf.gz" \
  "${noir_vectors}/oprf/witness.gz"
cp "${repo_root}/noir-examples/oprf/Prover.toml" \
  "${noir_vectors}/oprf/Prover.toml"

bun run "${script_dir}/configure-mopro-native.ts" "${project_root}" "${artifact_root}"
(
  cd "${project_root}"
  cargo generate-lockfile
  PATH="$(dirname "${w2c2}"):${PATH}" cargo check --release
  if [[ "${build_ios}" == "true" ]]; then
    PATH="$(dirname "${w2c2}"):${PATH}" "${mopro}" build \
      --mode release \
      --platforms ios \
      --architectures aarch64-apple-ios \
      --no-auto-update
    if [[ ! -d "${project_root}/MoproiOSBindings/MoproBindings.xcframework" ]]; then
      echo "error: Mopro did not create the expected iOS XCFramework" >&2
      exit 1
    fi
  fi
  if [[ "${build_android}" == "true" ]]; then
    android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
    android_ndk="${ANDROID_NDK_HOME:-}"
    if [[ -z "${android_ndk}" && -d "${android_sdk}/ndk" ]]; then
      android_ndk="$(
        find "${android_sdk}/ndk" -mindepth 1 -maxdepth 1 -type d |
          sort -V |
          tail -n 1
      )"
    fi
    if [[ -z "${android_ndk}" || ! -d "${android_ndk}" ]]; then
      echo "error: Android NDK not found; set ANDROID_NDK_HOME" >&2
      exit 1
    fi
    ANDROID_NDK_HOME="${android_ndk}" \
      PATH="$(dirname "${w2c2}"):${PATH}" "${mopro}" build \
      --mode release \
      --platforms android \
      --architectures aarch64-linux-android \
      --no-auto-update
    if [[ ! -d "${project_root}/MoproAndroidBindings" ]]; then
      echo "error: Mopro did not create the expected Android bindings" >&2
      exit 1
    fi
  fi
)

echo "Mopro Circom/Arkworks and Noir/Barretenberg native adapters are ready at ${project_root}"
