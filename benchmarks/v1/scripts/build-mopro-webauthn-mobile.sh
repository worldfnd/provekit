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
project="${repo_root}/target/v1-benchmarks/mopro/provekit-v1-mobile-adapters"
manifest="${repo_root}/target/v1-benchmarks/circom/webauthn/manifest.json"
zkey="${repo_root}/target/v1-benchmarks/groth16/webauthn/webauthn_default_benchmark.zkey"
output="${repo_root}/target/v1-benchmarks/mopro-webauthn-arkworks-${platform}"

for command in cargo-mobench jq openssl; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/prepare-mopro-native-adapters.sh"
expected_sha="$(
  jq -er \
    '.artifacts[] | select(.path | endswith("webauthn_default_benchmark.zkey")) | .sha256' \
    "${manifest}"
)"
actual_sha="$(openssl dgst -sha256 "${zkey}" | awk '{print tolower($NF)}')"
[[ "${actual_sha}" == "${expected_sha}" ]] || {
  echo "error: WebAuthn zkey hash mismatch" >&2
  exit 1
}

function_list="$(cargo-mobench list --crate-path "${project}")"
grep -F 'provekit_v1_mobile_adapters::bench_webauthn_arkworks_prove' \
  <<<"${function_list}" >/dev/null

if [[ "${platform}" == "ios" ]]; then
  for command in bun cp xcodegen; do
    command -v "${command}" >/dev/null 2>&1 || {
      echo "error: ${command} is required" >&2
      exit 1
    }
  done
  cargo-mobench build \
    --target ios \
    --release \
    --ios-deployment-target 15.0 \
    --crate-path "${project}" \
    --output-dir "${output}" \
    --progress

  ios_project="${output}/ios/BenchRunner"
  resources="${ios_project}/BenchRunner/Resources"
  mkdir -p "${resources}"
  if [[ -n "${V1_WEBAUTHN_REMOTE_ZKEY_MANIFEST:-}" ]]; then
    [[ -f "${V1_WEBAUTHN_REMOTE_ZKEY_MANIFEST}" ]] || {
      echo "error: V1_WEBAUTHN_REMOTE_ZKEY_MANIFEST does not exist" >&2
      exit 1
    }
    bun "${script_dir}/patch-ios-remote-proving-key.ts" \
      "${ios_project}/BenchRunner/BenchRunnerFFI.swift"
    cp -c \
      "${V1_WEBAUTHN_REMOTE_ZKEY_MANIFEST}" \
      "${resources}/proving_key_remote.json" 2>/dev/null ||
      cp \
        "${V1_WEBAUTHN_REMOTE_ZKEY_MANIFEST}" \
        "${resources}/proving_key_remote.json"
  else
    cp -c "${zkey}" "${resources}/webauthn_default_benchmark.zkey" 2>/dev/null ||
      cp "${zkey}" "${resources}/webauthn_default_benchmark.zkey"
  fi
  jq -n \
    --arg function \
      "provekit_v1_mobile_adapters::bench_webauthn_arkworks_prove" \
    '{function: $function, iterations: 5, warmup: 1}' \
    >"${resources}/bench_spec.json"
  (
    cd "${ios_project}"
    xcodegen generate
  )
  cargo-mobench package-ipa \
    --method adhoc \
    --crate-path "${project}" \
    --output-dir "${output}" \
    --yes \
    --non-interactive
  cargo-mobench package-xcuitest \
    --crate-path "${project}" \
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

  cargo-mobench build \
    --target android \
    --release \
    --crate-path "${project}" \
    --output-dir "${output}" \
    --progress
  android_project="${output}/android"
  jni_libs_root="${android_project}/app/src/main/jniLibs"
  gradle_file="${android_project}/app/build.gradle"
  perl -0pi -e \
    's/jniLibs \{\n/jniLibs {\n            useLegacyPackaging true\n/' \
    "${gradle_file}"
  for abi in arm64-v8a armeabi-v7a; do
    jni_libs="${jni_libs_root}/${abi}"
    [[ -d "${jni_libs}" ]] || continue
    cp -c "${zkey}" "${jni_libs}/libmobench_webauthn_zkey.so" 2>/dev/null ||
      cp "${zkey}" "${jni_libs}/libmobench_webauthn_zkey.so"
  done
  (
    cd "${android_project}"
    ./gradlew assembleRelease assembleReleaseAndroidTest \
      -PmobenchTestBuildType=release
  )
  app="${android_project}/app/build/outputs/apk/release/app-release-unsigned.apk"
  test_apk="${android_project}/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk"
  apk_entries="$(unzip -l "${app}")"
  for abi in arm64-v8a armeabi-v7a; do
    grep -F "lib/${abi}/libmobench_webauthn_zkey.so" \
      <<<"${apk_entries}" >/dev/null
  done
  shasum -a 256 "${app}" "${test_apk}"
fi
