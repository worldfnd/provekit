#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
prebuilt_root="${V1_RAPIDSNARK_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/rapidsnark-ios-prebuilt}"

for command in cargo-mobench cp jq shasum stat xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

content_digest() {
  local files=(
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/Cargo.lock"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/Cargo.toml"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/build.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/src/lib.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/src/rapidsnark.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile-register/Cargo.toml"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile-register/src/lib.rs"
    "${repo_root}/target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-ios/SHA256SUMS"
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
  # Mobench's prebuilt contract requires a full 40-hex source identifier.
  # This is a deterministic SHA-1 over SHA-256 content digests, rather than a
  # claim that the dirty benchmark adapter already has a Git commit.
  printf '%s\n' "${hashes[@]}" | shasum | awk '{print $1}'
}

source_digest="$(content_digest)"

prepare_workload() {
  local workload="$1"
  local crate="$2"
  local output="$3"
  local crate_name
  crate_name="$(
    sed -n 's/^name = "\(.*\)"/\1/p' "${crate}/Cargo.toml" |
      head -1 |
      tr - _
  )"

  local project="${output}/ios/BenchRunner"
  local resources="${project}/BenchRunner/Resources"
  local suite="${output}/ios/BenchRunnerUITests.zip"
  [[ -d "${resources}" && -f "${suite}" ]] || {
    echo "error: build ${workload} first with build-rapidsnark-mobile-ios.sh" >&2
    return 1
  }

  local phase function destination app test_copy app_size app_hash test_size test_hash
  for phase in prove verify proof_verify; do
    function="${crate_name}::bench_passport_rapidsnark_${phase}"
    destination="${prebuilt_root}/${workload}-${phase}"
    mkdir -p "${destination}/entries/0000"

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

    app="${destination}/entries/0000/app.ipa"
    test_copy="${destination}/entries/0000/test-suite.zip"
    cp -c "${output}/ios/BenchRunner.ipa" "${app}" 2>/dev/null ||
      cp "${output}/ios/BenchRunner.ipa" "${app}"
    cp -c "${suite}" "${test_copy}" 2>/dev/null || cp "${suite}" "${test_copy}"

    app_size="$(stat -f '%z' "${app}")"
    app_hash="$(shasum -a 256 "${app}" | awk '{print $1}')"
    test_size="$(stat -f '%z' "${test_copy}")"
    test_hash="$(shasum -a 256 "${test_copy}" | awk '{print $1}')"

    jq -n \
      --arg source_digest "${source_digest}" \
      --arg function "${function}" \
      --arg app_hash "${app_hash}" \
      --arg test_hash "${test_hash}" \
      --argjson app_size "${app_size}" \
      --argjson test_size "${test_size}" \
      '{
        schema: "mobench.prebuilt.v1",
        source_sha: $source_digest,
        platform: "ios",
        build_profile: "release",
        mobench_version: "0.2.0",
        abi: {
          benchmark: "mobench-bench-spec-v1",
          runner: "browserstack-xcuitest-v2"
        },
        entries: [{
          function: $function,
          iterations: 5,
          warmup: 1,
          completion_timeout_secs: 7200,
          artifacts: [
            {
              kind: "ios-app",
              path: "entries/0000/app.ipa",
              size: $app_size,
              sha256: $app_hash
            },
            {
              kind: "ios-test-suite",
              path: "entries/0000/test-suite.zip",
              size: $test_size,
              sha256: $test_hash
            }
          ]
        }]
      }' >"${destination}/manifest.json"

    unzip -p "${app}" 'Payload/*.app/bench_spec.json' |
      jq -e --arg function "${function}" \
        '.function == $function and .iterations == 5 and .warmup == 1' >/dev/null
    echo "${destination}/manifest.json"
  done
}

prepare_workload \
  passport-disclose \
  "${benchmark_root}/rapidsnark/rapidsnark-mobile" \
  "${repo_root}/target/v1-benchmarks/rapidsnark-disclose-ios"
prepare_workload \
  passport-register \
  "${benchmark_root}/rapidsnark/rapidsnark-mobile-register" \
  "${repo_root}/target/v1-benchmarks/rapidsnark-register-ios"
