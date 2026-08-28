#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
prebuilt_root="${V1_RAPIDSNARK_ANDROID_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/rapidsnark-android-prebuilt}"

for command in cp jq shasum stat unzip; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
if [[ -z "${JAVA_HOME:-}" &&
  -x "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java" ]]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
if [[ -z "${ANDROID_HOME:-}" && -d "${HOME}/Library/Android/sdk" ]]; then
  export ANDROID_HOME="${HOME}/Library/Android/sdk"
fi
[[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] || {
  echo "error: set JAVA_HOME to a Java 17+ runtime" >&2
  exit 1
}
[[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME}" ]] || {
  echo "error: set ANDROID_HOME to the Android SDK" >&2
  exit 1
}

content_digest() {
  local files=(
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/Cargo.lock"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/Cargo.toml"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/build.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/src/lib.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile/src/rapidsnark.rs"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile-register/Cargo.toml"
    "${benchmark_root}/rapidsnark/rapidsnark-mobile-register/src/lib.rs"
    "${repo_root}/target/v1-benchmarks/native-libs/rapidsnark/aarch64-linux-android/SHA256SUMS"
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

  local project="${output}/android"
  local assets="${project}/app/src/main/assets"
  local built_app="${project}/app/build/outputs/apk/release/app-release-unsigned.apk"
  local built_test="${project}/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk"
  [[ -d "${project}" && -f "${built_app}" && -f "${built_test}" ]] || {
    echo "error: build ${workload} first with build-rapidsnark-mobile-android.sh" >&2
    return 1
  }
  mkdir -p "${assets}"

  local phase function destination app test_copy app_size app_hash test_size test_hash
  for phase in prove verify proof_verify; do
    function="${crate_name}::bench_passport_rapidsnark_${phase}"
    destination="${prebuilt_root}/${workload}-${phase}"
    mkdir -p "${destination}/entries/0000"

    jq -n \
      --arg function "${function}" \
      '{function: $function, iterations: 5, warmup: 1}' \
      >"${assets}/bench_spec.json"
    (
      cd "${project}"
      ./gradlew assembleRelease assembleReleaseAndroidTest -PmobenchTestBuildType=release >/dev/null
    )

    app="${destination}/entries/0000/app.apk"
    test_copy="${destination}/entries/0000/test.apk"
    cp -c "${built_app}" "${app}" 2>/dev/null || cp "${built_app}" "${app}"
    cp -c "${built_test}" "${test_copy}" 2>/dev/null || cp "${built_test}" "${test_copy}"

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
        platform: "android",
        build_profile: "release",
        mobench_version: "0.1.48",
        abi: {
          benchmark: "mobench-bench-spec-v1",
          runner: "browserstack-espresso-v2"
        },
        entries: [{
          function: $function,
          iterations: 5,
          warmup: 1,
          completion_timeout_secs: 7200,
          artifacts: [
            {
              kind: "android-app",
              path: "entries/0000/app.apk",
              size: $app_size,
              sha256: $app_hash
            },
            {
              kind: "android-test-suite",
              path: "entries/0000/test.apk",
              size: $test_size,
              sha256: $test_hash
            }
          ]
        }]
      }' >"${destination}/manifest.json"

    unzip -p "${app}" assets/bench_spec.json |
      jq -e --arg function "${function}" \
        '.function == $function and .iterations == 5 and .warmup == 1' >/dev/null
    echo "${destination}/manifest.json"
  done
}

prepare_workload \
  passport-disclose \
  "${benchmark_root}/rapidsnark/rapidsnark-mobile" \
  "${repo_root}/target/v1-benchmarks/rapidsnark-disclose-android"
prepare_workload \
  passport-register \
  "${benchmark_root}/rapidsnark/rapidsnark-mobile-register" \
  "${repo_root}/target/v1-benchmarks/rapidsnark-register-android"
