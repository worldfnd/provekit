#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
scaffold_crate="${benchmark_root}/mobench-ios-scaffold"
prebuilt_root="${V1_RAPIDSNARK_CORE_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/rapidsnark-core-ios-prebuilt}"
build_parent="${repo_root}/target/v1-benchmarks"
passport_assets="${benchmark_root}/circom/web/dist/assets/passport"
passport_witnesses="${repo_root}/target/v1-benchmarks/circom/passport"
webauthn_assets="${benchmark_root}/circom/web/dist/assets/webauthn"
remote_webauthn_zkey_url="${MOBENCH_WEBAUTHN_ZKEY_URL:-}"
remote_passport_p1_zkey_url="${MOBENCH_PASSPORT_P1_ZKEY_URL:-}"
passport_p1_zkey="${repo_root}/target/v1-benchmarks/groth16/passport_p1/passport_p1_final.zkey"
passport_p1_witness="${repo_root}/target/v1-benchmarks/circom-witnesses/passport_p1/native.wtns"
passport_p1_vkey="${repo_root}/target/v1-benchmarks/groth16/passport_p1/verification_key.json"
selected_workloads="${V1_RAPIDSNARK_CORE_IOS_WORKLOADS:-passport-disclose,passport-register,passport-p1,webauthn}"
iterations="${V1_IOS_ITERATIONS:-5}"
warmup="${V1_IOS_WARMUP:-1}"

workload_selected() {
  case ",${selected_workloads}," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

for workload in ${selected_workloads//,/ }; do
  case "${workload}" in
    passport-disclose | passport-register | passport-p1 | webauthn) ;;
    *)
      echo "error: unsupported V1_RAPIDSNARK_CORE_IOS_WORKLOADS entry: ${workload}" >&2
      exit 2
      ;;
  esac
done

for command in bun cargo cargo-mobench cp jq shasum stat unzip xcodebuild xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

compute_content_sha256() {
  shasum -a 256 \
    "${benchmark_root}/rapidsnark-mobile/Cargo.toml" \
    "${benchmark_root}/rapidsnark-mobile/src/lib.rs" \
    "${benchmark_root}/rapidsnark-mobile/src/rapidsnark.rs" \
    "${benchmark_root}/rapidsnark-mobile/src/live_witness.rs" \
    "${benchmark_root}/rapidsnark-mobile-register/Cargo.toml" \
    "${benchmark_root}/rapidsnark-mobile-webauthn/Cargo.toml" \
    "${benchmark_root}/rapidsnark-mobile-webauthn/Cargo.lock" \
    "${benchmark_root}/rapidsnark-mobile-webauthn/src/lib.rs" \
    "${scaffold_crate}/Cargo.toml" \
    "${scaffold_crate}/src/main.rs" \
    "${BASH_SOURCE[0]}" \
    "${benchmark_root}/rapidsnark-ios-single-thread.patch" \
    "${benchmark_root}/rapidsnark-ios-low-memory.patch" \
    "${script_dir}/build-rapidsnark-ios-libs.sh" \
    "${script_dir}/patch-ios-remote-proving-key.ts" \
    "${script_dir}/patch-ios-runner-json.ts" \
    "${script_dir}/patch-ios15-xcuitest-suite.sh" \
    "${passport_assets}/vc_and_disclose.zkey" \
    "${passport_witnesses}/vc_and_disclose.wtns" \
    "${passport_assets}/vc_and_disclose.vkey.json" \
    "${passport_assets}/vc_and_disclose.wasm" \
    "${passport_assets}/vc_and_disclose.input.json" \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.zkey" \
    "${passport_witnesses}/register_sha256_sha256_sha256_rsa_65537_4096.wtns" \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.vkey.json" \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.wasm" \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.input.json" \
    "${passport_p1_zkey}" \
    "${passport_p1_witness}" \
    "${passport_p1_vkey}" \
    "${repo_root}/target/v1-benchmarks/circom/passport_p1/passport_p1_js/passport_p1.wasm" \
    "${benchmark_root}/circom/fixtures/passport_p1/input.json" \
    "${webauthn_assets}/webauthn_default.zkey" \
    "${repo_root}/target/v1-benchmarks/circom/webauthn/fixture.wtns" \
    "${webauthn_assets}/webauthn_default.vkey.json" \
    "${webauthn_assets}/webauthn_default.wasm" \
    "${webauthn_assets}/webauthn_default.input.json" |
    awk '{print $1}' |
    {
      cat
      printf '%s\n' "${remote_webauthn_zkey_url}"
      printf '%s\n' "${remote_passport_p1_zkey_url}"
      printf '%s\n' "${selected_workloads}"
    } |
    shasum -a 256 |
    awk '{print $1}'
}

content_manifest="${prebuilt_root}.content.json"
content_sha256="$(printf '%s\n%s\n%s\n' "$(compute_content_sha256)" "${iterations}" "${warmup}" | shasum -a 256 | awk '{print $1}')"
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
    --expected-iterations "${iterations}" \
    --expected-warmup "${warmup}" \
    --devices "iPhone SE 2022-15" \
    --max-completion-timeout-secs 7200 >/dev/null
  echo "Reusing frozen ${prebuilt_root}/manifest.json"
  exit 0
fi

case "${prebuilt_root}" in
  "${repo_root}/target/v1-benchmarks/"*)
    rm -rf "${prebuilt_root}/entries"
    ;;
  *)
    echo "error: refusing to clear unexpected prebuilt root: ${prebuilt_root}" >&2
    exit 1
    ;;
esac

"${script_dir}/build-rapidsnark-ios-libs.sh" >/dev/null

work_root="$(mktemp -d "${build_parent}/rapidsnark-core-ios-package.XXXXXX")"
cleanup() {
  case "${work_root}" in
    "${build_parent}"/rapidsnark-core-ios-package.*)
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

prepare_workload() {
  local workload="$1"
  local crate="$2"
  local library_name="$3"
  local function_prefix="$4"
  local zkey="$5"
  local witness="$6"
  local verification_key="$7"
  shift 7
  local phases=("$@")
  local output="${work_root}/${workload}"
  local cargo_target="${repo_root}/target/v1-benchmarks/rapidsnark-${workload}-cargo"
  local project="${output}/ios/BenchRunner"
  local resources="${project}/BenchRunner/Resources"
  local header_dir="${project}/BenchRunner/Generated"
  local static_library="${cargo_target}/aarch64-apple-ios/release/lib${library_name}.a"
  local xcframework="${output}/ios/${library_name}.xcframework"

  for required in "${zkey}" "${witness}" "${verification_key}"; do
    [[ -f "${required}" ]] || {
      echo "error: missing frozen ${workload} fixture ${required}" >&2
      exit 1
    }
  done

  if [[ "${workload}" == "passport-p1" ]]; then
    cargo build \
      --manifest-path "${crate}/Cargo.toml" \
      --target aarch64-apple-ios \
      --release \
      --target-dir "${cargo_target}" \
      --no-default-features \
      --features passport-p1
  else
    cargo build \
      --manifest-path "${crate}/Cargo.toml" \
      --target aarch64-apple-ios \
      --release \
      --target-dir "${cargo_target}"
  fi

  cargo run \
    --quiet \
    --manifest-path "${scaffold_crate}/Cargo.toml" \
    -- \
    "${output}" \
    "${library_name}" \
    "${library_name}::${function_prefix}_proof_verify"

  bun "${script_dir}/patch-ios-runner-json.ts" \
    "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
  local remote_zkey_url=""
  case "${workload}" in
    webauthn) remote_zkey_url="${remote_webauthn_zkey_url}" ;;
    passport-p1) remote_zkey_url="${remote_passport_p1_zkey_url}" ;;
  esac
  if [[ -n "${remote_zkey_url}" ]]; then
    bun "${script_dir}/patch-ios-remote-proving-key.ts" \
      "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
  fi

  xcodebuild -create-xcframework \
    -library "${static_library}" \
    -headers "${header_dir}" \
    -output "${xcframework}" >/dev/null

  mkdir -p "${resources}"
  if [[ -n "${remote_zkey_url}" ]]; then
    jq -n \
      --arg url "${remote_zkey_url}" \
      --arg sha256 "$(shasum -a 256 "${zkey}" | awk '{print $1}')" \
      --argjson bytes "$(stat -f '%z' "${zkey}")" \
      '{url:$url,bytes:$bytes,sha256:$sha256}' \
      >"${resources}/proving_key_remote.json"
  else
    copy_fixture "${zkey}" "${resources}/proving_key.zkey"
  fi
  copy_fixture "${witness}" "${resources}/reference.wtns"
  copy_fixture "${verification_key}" "${resources}/verification_key.json"

  local phase function entry destination app suite
  local app_size suite_size app_hash suite_hash
  for phase in "${phases[@]}"; do
    function="${library_name}::${function_prefix}_${phase}"
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
      "${output}/ios/BenchRunnerUITests.zip" >/dev/null

    app="${destination}/app.ipa"
    suite="${destination}/test-suite.zip"
    copy_fixture "${output}/ios/BenchRunner.ipa" "${app}"
    copy_fixture "${output}/ios/BenchRunnerUITests.zip" "${suite}"
    unzip -p "${app}" 'Payload/*.app/bench_spec.json' |
      jq -e \
        --arg function "${function}" \
        --argjson iterations "${iterations}" \
        --argjson warmup "${warmup}" \
        '.function == $function and .iterations == $iterations and .warmup == $warmup' \
        >/dev/null

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
}

if workload_selected passport-disclose; then
  prepare_workload \
    passport-disclose \
    "${benchmark_root}/rapidsnark-mobile" \
    provekit_v1_rapidsnark_mobile \
    bench_passport_rapidsnark \
    "${passport_assets}/vc_and_disclose.zkey" \
    "${passport_witnesses}/vc_and_disclose.wtns" \
    "${passport_assets}/vc_and_disclose.vkey.json" \
    input_to_proof
fi
if workload_selected passport-register; then
  prepare_workload \
    passport-register \
    "${benchmark_root}/rapidsnark-mobile-register" \
    provekit_v1_rapidsnark_mobile_register \
    bench_passport_rapidsnark \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.zkey" \
    "${passport_witnesses}/register_sha256_sha256_sha256_rsa_65537_4096.wtns" \
    "${passport_assets}/register_sha256_sha256_sha256_rsa_65537_4096.vkey.json" \
    input_to_proof
fi
if workload_selected passport-p1; then
  [[ -n "${remote_passport_p1_zkey_url}" ]] || {
    echo "error: MOBENCH_PASSPORT_P1_ZKEY_URL is required for passport-p1" >&2
    exit 2
  }
  prepare_workload \
    passport-p1 \
    "${benchmark_root}/rapidsnark-mobile" \
    provekit_v1_rapidsnark_mobile \
    bench_passport_p1_rapidsnark \
    "${passport_p1_zkey}" \
    "${passport_p1_witness}" \
    "${passport_p1_vkey}" \
    input_to_proof
fi
if workload_selected webauthn; then
  prepare_workload \
    webauthn \
    "${benchmark_root}/rapidsnark-mobile-webauthn" \
    provekit_v1_rapidsnark_mobile_webauthn \
    bench_webauthn_rapidsnark \
    "${webauthn_assets}/webauthn_default.zkey" \
    "${repo_root}/target/v1-benchmarks/circom/webauthn/fixture.wtns" \
    "${webauthn_assets}/webauthn_default.vkey.json" \
    input_to_proof
fi

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
    schema: "provekit.rapidsnark-core-content.v1",
    source_sha: $source_sha,
    content_sha256: $content_sha256,
    prebuilt_manifest_sha256: $manifest_sha256
  }' >"${content_manifest}"

jq -e --argjson expected "${entry_index}" \
  '.entries | length == $expected' "${manifest}" >/dev/null
echo "${manifest}"
