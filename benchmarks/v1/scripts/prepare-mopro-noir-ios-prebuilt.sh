#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
crate="${repo_root}/target/v1-benchmarks/mopro/provekit-v1-mobile-adapters"
output="${repo_root}/target/v1-benchmarks/mopro-noir-ios"
prebuilt_root="${V1_MOPRO_NOIR_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/mopro-noir-ios-prebuilt}"
project="${output}/ios/BenchRunner"
resources="${project}/BenchRunner/Resources"
iterations="${V1_IOS_ITERATIONS:-5}"
warmup="${V1_IOS_WARMUP:-1}"
cold_launches="${V1_IOS_COLD_LAUNCHES:-1}"

for command in bun cargo-mobench cp jq shasum stat xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

[[ -d "${project}" &&
  -f "${output}/ios/provekit_v1_mobile_adapters.xcframework/Info.plist" ]] || {
  echo "error: build the arm64 Mopro Noir iOS runner first" >&2
  exit 1
}
mkdir -p "${resources}" "${prebuilt_root}/entries"
bun "${script_dir}/patch-ios-runner-json.ts" \
  "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
if ((cold_launches > 1)); then
  bun "${script_dir}/patch-ios-cold-launches.ts" \
    "${project}/BenchRunnerUITests/BenchRunnerUITests.swift" \
    "${cold_launches}" >/dev/null
fi
cp -c \
  "${repo_root}/target/v1-benchmarks/noir-srs/noir_beta19_campaign.dat" \
  "${resources}/noir_beta19_campaign.dat" 2>/dev/null ||
  cp \
    "${repo_root}/target/v1-benchmarks/noir-srs/noir_beta19_campaign.dat" \
    "${resources}/noir_beta19_campaign.dat"

content_digest() {
  local files=(
    "${benchmark_root}/mopro/noir_mobench.rs"
    "${benchmark_root}/mopro/noir_srs_host.rs"
    "${benchmark_root}/mopro/ios15_charconv_shim.cpp"
    "${benchmark_root}/scripts/configure-mopro-native.ts"
    "${benchmark_root}/scripts/prepare-mopro-native-adapters.sh"
    "${benchmark_root}/scripts/prepare-noir-beta19-srs.sh"
    "${BASH_SOURCE[0]}"
    "${script_dir}/patch-ios-runner-json.ts"
    "${script_dir}/patch-ios-cold-launches.ts"
    "${script_dir}/preflight-ios15-charconv.sh"
    "${script_dir}/patch-ios15-xcuitest-suite.sh"
    "${benchmark_root}/toolchains.lock.json"
    "${crate}/Cargo.lock"
    "${output}/ios/provekit_v1_mobile_adapters.xcframework/ios-arm64/libprovekit_v1_mobile_adapters.a"
    "${crate}/test-vectors/noir/campaign/webauthn/circuit.json"
    "${crate}/test-vectors/noir/campaign/webauthn/witness.gz"
    "${crate}/test-vectors/noir/campaign/webauthn/Prover.toml"
    "${crate}/test-vectors/noir/campaign/passport/circuit.json"
    "${crate}/test-vectors/noir/campaign/passport/witness.gz"
    "${crate}/test-vectors/noir/campaign/passport/Prover.toml"
    "${crate}/test-vectors/noir/campaign/passport_p1/circuit.json"
    "${crate}/test-vectors/noir/campaign/passport_p1/witness.gz"
    "${crate}/test-vectors/noir/campaign/passport_p1/Prover.toml"
    "${crate}/test-vectors/noir/campaign/oprf/circuit.json"
    "${crate}/test-vectors/noir/campaign/oprf/witness.gz"
    "${crate}/test-vectors/noir/campaign/oprf/Prover.toml"
    "${repo_root}/target/v1-benchmarks/noir-srs/noir_beta19_campaign.dat"
  )
  local file
  for file in "${files[@]}"; do
    [[ -f "${file}" ]] || {
      echo "error: digest input missing: ${file}" >&2
      return 1
    }
    shasum -a 256 "${file}" | awk '{print $1}'
  done | shasum -a 256 | awk '{print $1}'
}

source_sha="$(git -C "${repo_root}" rev-parse HEAD)"
content_sha256="$(printf '%s\n%s\n%s\n%s\n' "$(content_digest)" "${iterations}" "${warmup}" "${cold_launches}" | shasum -a 256 | awk '{print $1}')"
manifest="${prebuilt_root}/manifest.json"
content_manifest="${prebuilt_root}.content.json"
recorded_content_sha256=""
recorded_manifest_sha256=""
actual_manifest_sha256=""
if [[ -f "${manifest}" && -f "${content_manifest}" ]]; then
  recorded_content_sha256="$(jq -er '.content_sha256' "${content_manifest}")"
  recorded_manifest_sha256="$(
    jq -er '.prebuilt_manifest_sha256' "${content_manifest}"
  )"
  actual_manifest_sha256="$(
    shasum -a 256 "${manifest}" | awk '{print $1}'
  )"
fi
if [[ -f "${manifest}" && -f "${content_manifest}" ]] &&
  [[ "${recorded_content_sha256}" == "${content_sha256}" ]] &&
  [[ "${recorded_manifest_sha256}" == "${actual_manifest_sha256}" ]]; then
  existing_source_sha="$(jq -er '.source_sha' "${manifest}")"
  existing_functions="$(jq -c '[.entries[].function]' "${manifest}")"
  cargo-mobench ci run-prebuilt \
    --dry-run \
    --manifest "${manifest}" \
    --expected-source-sha "${existing_source_sha}" \
    --expected-platform ios \
    --expected-functions "${existing_functions}" \
    --expected-iterations "${iterations}" \
    --expected-warmup "${warmup}" \
    --devices "iPhone SE 2022-15" \
    --max-completion-timeout-secs 7200 >/dev/null
  echo "Reusing frozen ${manifest}"
  exit 0
fi

entries_file="$(mktemp "${TMPDIR:-/tmp}/mopro-noir-ios-entries.XXXXXX")"
cleanup() {
  rm -f "${entries_file}"
}
trap cleanup EXIT
: >"${entries_file}"

functions=(
  provekit_v1_mobile_adapters::bench_webauthn_barretenberg_input_to_proof
  provekit_v1_mobile_adapters::bench_passport_barretenberg_input_to_proof
  provekit_v1_mobile_adapters::bench_passport_p1_barretenberg_input_to_proof
  provekit_v1_mobile_adapters::bench_oprf_barretenberg_input_to_proof
)
for index in "${!functions[@]}"; do
  function="${functions[$index]}"
  entry="$(printf '%04d' "${index}")"
  destination="${prebuilt_root}/entries/${entry}"
  mkdir -p "${destination}"

  jq -n --argjson iterations "${iterations}" --argjson warmup "${warmup}" \
    --arg function "${function}" \
    '{function: $function, iterations: $iterations, warmup: $warmup}' \
    >"${resources}/bench_spec.json"
  (
    cd "${project}"
    xcodegen generate >/dev/null
  )
  cargo-mobench package-ipa \
    --method adhoc \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive >/dev/null
  "${script_dir}/preflight-ios15-charconv.sh" \
    "${output}/ios/BenchRunner.ipa" >/dev/null
  cargo-mobench package-xcuitest \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive >/dev/null
  "${script_dir}/patch-ios15-xcuitest-suite.sh" \
    "${output}/ios/BenchRunnerUITests.zip" >/dev/null

  app="${destination}/app.ipa"
  suite="${destination}/test-suite.zip"
  cp -c "${output}/ios/BenchRunner.ipa" "${app}" 2>/dev/null ||
    cp "${output}/ios/BenchRunner.ipa" "${app}"
  cp -c "${output}/ios/BenchRunnerUITests.zip" "${suite}" 2>/dev/null ||
    cp "${output}/ios/BenchRunnerUITests.zip" "${suite}"

  app_size="$(stat -f '%z' "${app}")"
  suite_size="$(stat -f '%z' "${suite}")"
  app_hash="$(shasum -a 256 "${app}" | awk '{print $1}')"
  suite_hash="$(shasum -a 256 "${suite}" | awk '{print $1}')"
  jq -cn \
    --arg function "${function}" \
    --argjson iterations "${iterations}" \
    --argjson warmup "${warmup}" \
    --arg app_path "entries/${entry}/app.ipa" \
    --arg suite_path "entries/${entry}/test-suite.zip" \
    --arg app_hash "${app_hash}" \
    --arg suite_hash "${suite_hash}" \
    --argjson app_size "${app_size}" \
    --argjson suite_size "${suite_size}" \
    '{
      function: $function,
      iterations: $iterations,
      warmup: $warmup,
      completion_timeout_secs: 7200,
      artifacts: [
        {
          kind: "ios-app",
          path: $app_path,
          size: $app_size,
          sha256: $app_hash
        },
        {
          kind: "ios-test-suite",
          path: $suite_path,
          size: $suite_size,
          sha256: $suite_hash
        }
      ]
    }' >>"${entries_file}"
done

jq -s \
  --arg source_sha "${source_sha}" \
  '{
    schema: "mobench.prebuilt.v1",
    source_sha: $source_sha,
    platform: "ios",
    build_profile: "release",
    mobench_version: "0.2.0",
    abi: {
      benchmark: "mobench-bench-spec-v1",
      runner: "browserstack-xcuitest-v2"
    },
    entries: .
  }' "${entries_file}" >"${manifest}"

jq -n \
  --arg source_sha "${source_sha}" \
  --arg content_sha256 "${content_sha256}" \
  --arg manifest_sha256 "$(shasum -a 256 "${manifest}" | awk '{print $1}')" \
  '{
    schema: "provekit.mopro-noir-content.v1",
    source_sha: $source_sha,
    content_sha256: $content_sha256,
    prebuilt_manifest_sha256: $manifest_sha256
  }' >"${content_manifest}"

echo "${manifest}"
