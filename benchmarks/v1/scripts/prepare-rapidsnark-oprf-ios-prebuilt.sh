#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
crate="${benchmark_root}/rapidsnark-mobile-oprf"
scaffold_crate="${benchmark_root}/mobench-ios-scaffold"
prebuilt_root="${V1_RAPIDSNARK_OPRF_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/rapidsnark-oprf-ios-prebuilt}"
build_parent="${repo_root}/target/v1-benchmarks"
library_name="provekit_v1_rapidsnark_mobile_oprf"
asset_root="${benchmark_root}/circom/web/dist/assets/oprf"
witness_root="${repo_root}/target/v1-benchmarks/circom/oprf"

for command in bun cargo cargo-mobench cp jq shasum stat unzip xcodebuild xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

compute_content_sha256() {
  shasum -a 256 \
    "${crate}/Cargo.toml" \
    "${crate}/src/lib.rs" \
    "${benchmark_root}/rapidsnark-mobile/build.rs" \
    "${benchmark_root}/rapidsnark-mobile/src/rapidsnark.rs" \
    "${scaffold_crate}/Cargo.toml" \
    "${scaffold_crate}/src/main.rs" \
    "${BASH_SOURCE[0]}" \
    "${script_dir}/build-rapidsnark-ios-libs.sh" \
    "${script_dir}/patch-ios-runner-json.ts" \
    "${script_dir}/patch-ios15-xcuitest-suite.sh" \
    "${asset_root}/oprf_query.zkey" \
    "${witness_root}/oprf_query.wtns" \
    "${asset_root}/oprf_query.vkey.json" \
    "${asset_root}/oprf_nullifier.zkey" \
    "${witness_root}/oprf_nullifier.wtns" \
    "${asset_root}/oprf_nullifier.vkey.json" |
    awk '{print $1}' |
    shasum -a 256 |
    awk '{print $1}'
}

content_manifest="${prebuilt_root}.content.json"
content_sha256="$(compute_content_sha256)"
recorded_content_sha256=""
recorded_manifest_sha256=""
actual_manifest_sha256=""
if [[ -f "${prebuilt_root}/manifest.json" && -f "${content_manifest}" ]]; then
  recorded_content_sha256="$(jq -er '.content_sha256' "${content_manifest}")"
  recorded_manifest_sha256="$(
    jq -er '.prebuilt_manifest_sha256' "${content_manifest}"
  )"
  actual_manifest_sha256="$(
    shasum -a 256 "${prebuilt_root}/manifest.json" | awk '{print $1}'
  )"
fi
if [[ -f "${prebuilt_root}/manifest.json" && -f "${content_manifest}" ]] &&
  [[ "${recorded_content_sha256}" == "${content_sha256}" ]] &&
  [[ "${recorded_manifest_sha256}" == "${actual_manifest_sha256}" ]]; then
  existing_source_sha="$(jq -er '.source_sha' "${prebuilt_root}/manifest.json")"
  existing_functions="$(
    jq -c '[.entries[].function]' "${prebuilt_root}/manifest.json"
  )"
  cargo-mobench ci run-prebuilt \
    --dry-run \
    --manifest "${prebuilt_root}/manifest.json" \
    --expected-source-sha "${existing_source_sha}" \
    --expected-platform ios \
    --expected-functions "${existing_functions}" \
    --expected-iterations 5 \
    --expected-warmup 1 \
    --devices "iPhone SE 2022-15" \
    --max-completion-timeout-secs 7200 >/dev/null
  echo "Reusing frozen ${prebuilt_root}/manifest.json"
  exit 0
fi

"${script_dir}/build-rapidsnark-ios-libs.sh" >/dev/null

work_root="$(mktemp -d "${build_parent}/rapidsnark-oprf-ios-package.XXXXXX")"
cleanup() {
  case "${work_root}" in
    "${build_parent}"/rapidsnark-oprf-ios-package.*)
      rm -rf "${work_root}"
      ;;
    *)
      echo "error: refusing to clean unexpected package path: ${work_root}" >&2
      ;;
  esac
}
trap cleanup EXIT

entries_file="${work_root}/entries.jsonl"
: >"${entries_file}"
entry_index=0

copy_fixture() {
  local source="$1"
  local destination="$2"
  cp -c "${source}" "${destination}" 2>/dev/null ||
    cp "${source}" "${destination}"
}

prepare_variant() {
  local variant="$1"
  local feature="$2"
  local zkey="$3"
  local witness="$4"
  local verification_key="$5"
  local output="${work_root}/${variant}"
  local cargo_target="${repo_root}/target/v1-benchmarks/rapidsnark-oprf-${variant}-cargo"
  local project="${output}/ios/BenchRunner"
  local resources="${project}/BenchRunner/Resources"
  local header_dir="${project}/BenchRunner/Generated"
  local static_library="${cargo_target}/aarch64-apple-ios/release/lib${library_name}.a"
  local xcframework="${output}/ios/${library_name}.xcframework"

  cargo build \
    --manifest-path "${crate}/Cargo.toml" \
    --target aarch64-apple-ios \
    --release \
    --no-default-features \
    --features "${feature}" \
    --target-dir "${cargo_target}"

  cargo run \
    --quiet \
    --manifest-path "${scaffold_crate}/Cargo.toml" \
    -- \
    "${output}" \
    "${library_name}" \
    "${library_name}::bench_oprf_${variant}_rapidsnark_proof_verify"

  bun "${script_dir}/patch-ios-runner-json.ts" \
    "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null

  xcodebuild -create-xcframework \
    -library "${static_library}" \
    -headers "${header_dir}" \
    -output "${xcframework}" >/dev/null

  mkdir -p "${resources}"
  copy_fixture "${zkey}" "${resources}/proving_key.zkey"
  copy_fixture "${witness}" "${resources}/reference.wtns"
  copy_fixture "${verification_key}" "${resources}/verification_key.json"

  local phase function entry destination app suite
  local app_size suite_size app_hash suite_hash
  for phase in prove; do
    function="${library_name}::bench_oprf_${variant}_rapidsnark_${phase}"
    entry="$(printf '%04d' "${entry_index}")"
    destination="${prebuilt_root}/entries/${entry}"
    mkdir -p "${destination}"

    jq -n \
      --arg function "${function}" \
      '{function: $function, iterations: 5, warmup: 1}' \
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
      "${output}/ios/BenchRunnerUITests.zip" >/dev/null

    app="${destination}/app.ipa"
    suite="${destination}/test-suite.zip"
    copy_fixture "${output}/ios/BenchRunner.ipa" "${app}"
    copy_fixture "${output}/ios/BenchRunnerUITests.zip" "${suite}"

    unzip -p "${app}" 'Payload/*.app/bench_spec.json' |
      jq -e \
        --arg function "${function}" \
        '.function == $function and .iterations == 5 and .warmup == 1' \
        >/dev/null

    app_size="$(stat -f '%z' "${app}")"
    suite_size="$(stat -f '%z' "${suite}")"
    app_hash="$(shasum -a 256 "${app}" | awk '{print $1}')"
    suite_hash="$(shasum -a 256 "${suite}" | awk '{print $1}')"
    jq -cn \
      --arg function "${function}" \
      --arg app_path "entries/${entry}/app.ipa" \
      --arg suite_path "entries/${entry}/test-suite.zip" \
      --arg app_hash "${app_hash}" \
      --arg suite_hash "${suite_hash}" \
      --argjson app_size "${app_size}" \
      --argjson suite_size "${suite_size}" \
      '{
        function: $function,
        iterations: 5,
        warmup: 1,
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
}

prepare_variant \
  query \
  oprf-query \
  "${asset_root}/oprf_query.zkey" \
  "${witness_root}/oprf_query.wtns" \
  "${asset_root}/oprf_query.vkey.json"
prepare_variant \
  nullifier \
  oprf-nullifier \
  "${asset_root}/oprf_nullifier.zkey" \
  "${witness_root}/oprf_nullifier.wtns" \
  "${asset_root}/oprf_nullifier.vkey.json"

mkdir -p "${prebuilt_root}"
source_sha="$(git -C "${repo_root}" rev-parse HEAD)"
manifest="${prebuilt_root}/manifest.json"
jq -s \
  --arg source_sha "${source_sha}" \
  '{
    schema: "mobench.prebuilt.v1",
    source_sha: $source_sha,
    platform: "ios",
    build_profile: "release",
    mobench_version: "0.1.48",
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
    schema: "provekit.rapidsnark-oprf-content.v1",
    source_sha: $source_sha,
    content_sha256: $content_sha256,
    prebuilt_manifest_sha256: $manifest_sha256
  }' >"${content_manifest}"

jq -e '.entries | length == 2' "${manifest}" >/dev/null
echo "${manifest}"
