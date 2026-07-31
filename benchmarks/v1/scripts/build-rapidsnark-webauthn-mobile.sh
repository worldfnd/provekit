#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <ios|android>" >&2
}

[[ $# -eq 1 ]] || {
  usage
  exit 2
}
platform="$1"
[[ "${platform}" == "ios" || "${platform}" == "android" ]] || {
  usage
  exit 2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
crate="${benchmark_root}/rapidsnark-mobile-webauthn"
fixture="${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16/webauthn"
output="${repo_root}/target/v1-benchmarks/rapidsnark-webauthn-${platform}"
manifest="${repo_root}/target/v1-benchmarks/circom/webauthn/manifest.json"
zkey="${repo_root}/target/v1-benchmarks/groth16/webauthn/webauthn_default_benchmark.zkey"
wtns="${repo_root}/target/v1-benchmarks/circom/webauthn/fixture.wtns"
verification_key="${repo_root}/target/v1-benchmarks/groth16/webauthn/verification_key.json"

for command in cargo-mobench cp jq openssl; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/prepare-webauthn-circom.sh"
for source in "${zkey}" "${wtns}" "${verification_key}"; do
  [[ -f "${source}" ]] || {
    echo "error: missing ${source}; run prepare-webauthn-circom.sh --setup" >&2
    exit 1
  }
  expected_sha="$(
    jq -er \
      --arg path "${source#"${repo_root}/"}" \
      '.artifacts[] | select(.path == $path) | .sha256' \
      "${manifest}"
  )"
  actual_sha="$(openssl dgst -sha256 "${source}" | awk '{print tolower($NF)}')"
  [[ "${actual_sha}" == "${expected_sha}" ]] || {
    echo "error: fixture hash mismatch for ${source}" >&2
    exit 1
  }
done

mkdir -p "${fixture}"
cp -c "${zkey}" "${fixture}/proving_key.zkey" 2>/dev/null ||
  cp "${zkey}" "${fixture}/proving_key.zkey"
cp -c "${wtns}" "${fixture}/reference.wtns" 2>/dev/null ||
  cp "${wtns}" "${fixture}/reference.wtns"
cp "${verification_key}" "${fixture}/verification_key.json"

for resource in proving_key.zkey reference.wtns verification_key.json; do
  [[ -f "${fixture}/${resource}" ]] || {
    echo "error: missing ${fixture}/${resource}" >&2
    exit 1
  }
done

if [[ "${platform}" == "ios" ]]; then
  command -v xcodegen >/dev/null 2>&1 || {
    echo "error: xcodegen is required" >&2
    exit 1
  }
  "${script_dir}/build-rapidsnark-ios-libs.sh" >/dev/null
  cargo-mobench build \
    --target ios \
    --release \
    --ios-deployment-target 15.0 \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --progress
  project="${output}/ios/BenchRunner"
  resources="${project}/BenchRunner/Resources"
  mkdir -p "${resources}"
  for resource in proving_key.zkey reference.wtns verification_key.json; do
    cp -c "${fixture}/${resource}" "${resources}/${resource}" 2>/dev/null ||
      cp "${fixture}/${resource}" "${resources}/${resource}"
  done
  (
    cd "${project}"
    xcodegen generate
  )
  cargo-mobench package-ipa \
    --method adhoc \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive
  cargo-mobench package-xcuitest \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive
  "${script_dir}/patch-ios15-xcuitest-suite.sh" \
    "${output}/ios/BenchRunnerUITests.zip"
  shasum -a 256 \
    "${output}/ios/BenchRunner.ipa" \
    "${output}/ios/BenchRunnerUITests.zip"
else
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

  "${script_dir}/build-rapidsnark-android-libs.sh" >/dev/null
  cargo-mobench build \
    --target android \
    --release \
    --crate-path "${crate}" \
    --output-dir "${output}" \
    --progress
  project="${output}/android"
  jni_libs="${project}/app/src/main/jniLibs/arm64-v8a"
  gradle_file="${project}/app/build.gradle"
  perl -0pi -e \
    's/jniLibs \{\n/jniLibs {\n            useLegacyPackaging true\n/' \
    "${gradle_file}"
  mkdir -p "${jni_libs}"
  cp -c "${fixture}/proving_key.zkey" "${jni_libs}/libmobench_proving_key.so" 2>/dev/null ||
    cp "${fixture}/proving_key.zkey" "${jni_libs}/libmobench_proving_key.so"
  cp -c "${fixture}/reference.wtns" "${jni_libs}/libmobench_reference_wtns.so" 2>/dev/null ||
    cp "${fixture}/reference.wtns" "${jni_libs}/libmobench_reference_wtns.so"
  cp -c "${fixture}/verification_key.json" "${jni_libs}/libmobench_verification_key.so" 2>/dev/null ||
    cp "${fixture}/verification_key.json" "${jni_libs}/libmobench_verification_key.so"
  (
    cd "${project}"
    ./gradlew assembleRelease assembleReleaseAndroidTest \
      -PmobenchTestBuildType=release
  )
  app="${project}/app/build/outputs/apk/release/app-release-unsigned.apk"
  test_apk="${project}/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk"
  unzip -l "${app}" |
    grep -F 'lib/arm64-v8a/libmobench_proving_key.so' >/dev/null
  shasum -a 256 "${app}" "${test_apk}"
fi
