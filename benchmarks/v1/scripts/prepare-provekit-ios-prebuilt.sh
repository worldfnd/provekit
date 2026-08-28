#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
crate="${repo_root}/bench-mobile"
output="${repo_root}/target/v1-benchmarks/provekit-ios"
prebuilt_root="${V1_PROVEKIT_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/provekit-ios-prebuilt}"
project="${output}/ios/BenchRunner"
resources="${project}/BenchRunner/Resources"
iterations="${V1_IOS_ITERATIONS:-5}"
warmup="${V1_IOS_WARMUP:-1}"
cold_launches="${V1_IOS_COLD_LAUNCHES:-1}"

for command in bun cargo-mobench cp git jq shasum stat xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

[[ -d "${project}" && -f "${output}/ios/bench_mobile.xcframework/Info.plist" ]] || {
  echo "error: build the iOS runner with cargo-mobench before preparing prebuilts" >&2
  exit 1
}
mkdir -p "${resources}"
bun "${script_dir}/patch-ios-runner-json.ts" \
  "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
if ((cold_launches > 1)); then
  bun "${script_dir}/patch-ios-cold-launches.ts" \
    "${project}/BenchRunnerUITests/BenchRunnerUITests.swift" \
    "${cold_launches}" >/dev/null
fi

content_digest() {
  local files=(
    "${crate}/Cargo.toml"
    "${crate}/build.rs"
    "${crate}/src/lib.rs"
    "${crate}/src/in_process.rs"
    "${crate}/src/examples.rs"
    "${crate}/src/passport.rs"
    "${repo_root}/Cargo.lock"
    "${repo_root}/mobench.toml"
    "${output}/ios/bench_mobile.xcframework/ios-arm64/bench_mobile.framework/bench_mobile"
    "${BASH_SOURCE[0]}"
    "${script_dir}/patch-ios-runner-json.ts"
    "${script_dir}/patch-ios-cold-launches.ts"
    "${script_dir}/patch-ios15-xcuitest-suite.sh"
    "${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts/passport_p1.json"
    "${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts/passport_p1.Prover.toml"
    "${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts/oprf.json"
    "${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts/oprf.Prover.toml"
  )
  local hashes=()
  local file
  for file in "${files[@]}"; do
    [[ -f "${file}" ]] || {
      echo "error: digest input missing: ${file}" >&2
      return 1
    }
    hashes+=("$(shasum -a 256 "${file}" | awk '{print $1}')")
  done
  printf '%s\n' "${hashes[@]}" | shasum | awk '{print $1}'
}

source_digest="$(printf '%s\n%s\n%s\n%s\n' "$(content_digest)" "${iterations}" "${warmup}" "${cold_launches}" | shasum -a 256 | awk '{print $1}')"
source_sha="$(git -C "${repo_root}" rev-parse HEAD)"
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
  [[ "${recorded_content_sha256}" == "${source_digest}" ]] &&
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

entries_file="$(mktemp "${TMPDIR:-/tmp}/provekit-ios-entries.XXXXXX")"
cleanup() {
  rm -f "${entries_file}"
}
trap cleanup EXIT

mkdir -p "${prebuilt_root}/entries"
: >"${entries_file}"

workloads=(passport_complete_age_check passport_p1 webauthn_assertion oprf)
phases=(input_to_proof)
entry_index=0
for workload in "${workloads[@]}"; do
  for phase in "${phases[@]}"; do
  function="bench_mobile::bench_${workload}_${phase}"
  entry="$(printf '%04d' "${entry_index}")"
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
  cargo-mobench package-xcuitest \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive >/dev/null
  "${script_dir}/patch-ios15-xcuitest-suite.sh" \
    "${output}/ios/BenchRunnerUITests.zip"

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
  entry_index=$((entry_index + 1))
  done
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
  --arg content_sha256 "${source_digest}" \
  --arg manifest_sha256 "$(shasum -a 256 "${manifest}" | awk '{print $1}')" \
  '{
    schema: "provekit.provekit-ios-content.v1",
    source_sha: $source_sha,
    content_sha256: $content_sha256,
    prebuilt_manifest_sha256: $manifest_sha256
  }' >"${content_manifest}"

echo "${manifest}"
