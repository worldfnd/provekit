#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <passport-disclose|passport-register>" >&2
}

[[ $# -eq 1 ]] || {
  usage
  exit 2
}

workload="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"

case "${workload}" in
  passport-disclose)
    crate="${benchmark_root}/rapidsnark/rapidsnark-mobile"
    fixture="${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16/vc_and_disclose"
    output="${repo_root}/target/v1-benchmarks/rapidsnark-disclose-android"
    ;;
  passport-register)
    crate="${benchmark_root}/rapidsnark/rapidsnark-mobile-register"
    fixture="${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16/register_sha256_sha256_sha256_rsa_65537_4096"
    output="${repo_root}/target/v1-benchmarks/rapidsnark-register-android"
    ;;
  *)
    usage
    exit 2
    ;;
esac

for command in cargo-mobench cp; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
if [[ -z "${JAVA_HOME:-}" &&
  -x "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java" ]]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
[[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] || {
  echo "error: set JAVA_HOME to a Java 17+ runtime" >&2
  exit 1
}
if [[ -z "${ANDROID_HOME:-}" && -d "${HOME}/Library/Android/sdk" ]]; then
  export ANDROID_HOME="${HOME}/Library/Android/sdk"
fi
[[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME}" ]] || {
  echo "error: set ANDROID_HOME to the Android SDK" >&2
  exit 1
}
for resource in proving_key.zkey reference.wtns verification_key.json; do
  [[ -f "${fixture}/resources/${resource}" ]] || {
    echo "error: missing ${fixture}/resources/${resource}" >&2
    exit 1
  }
done

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
cp -c "${fixture}/resources/proving_key.zkey" "${jni_libs}/libmobench_proving_key.so" 2>/dev/null ||
  cp "${fixture}/resources/proving_key.zkey" "${jni_libs}/libmobench_proving_key.so"
cp -c "${fixture}/resources/reference.wtns" "${jni_libs}/libmobench_reference_wtns.so" 2>/dev/null ||
  cp "${fixture}/resources/reference.wtns" "${jni_libs}/libmobench_reference_wtns.so"
cp -c "${fixture}/resources/verification_key.json" "${jni_libs}/libmobench_verification_key.so" 2>/dev/null ||
  cp "${fixture}/resources/verification_key.json" "${jni_libs}/libmobench_verification_key.so"

(
  cd "${project}"
  ./gradlew assembleRelease assembleReleaseAndroidTest -PmobenchTestBuildType=release
)

app="${project}/app/build/outputs/apk/release/app-release-unsigned.apk"
test_apk="${project}/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk"
[[ -f "${app}" && -f "${test_apk}" ]] || {
  echo "error: Android package did not produce the expected APKs" >&2
  exit 1
}
unzip -l "${app}" |
  grep -F 'lib/arm64-v8a/libmobench_proving_key.so' >/dev/null
shasum -a 256 "${app}" "${test_apk}"
