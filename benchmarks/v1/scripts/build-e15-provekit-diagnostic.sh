#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source "${script_dir}/android-env.sh"

output="${1:-${repo_root}/target/v1-benchmarks/e15-diagnostic-build}"
worker_process_suffix="${V1_E15_WORKER_PROCESS_SUFFIX:-:mobench_worker}"
[[ "${worker_process_suffix}" =~ ^:[A-Za-z0-9_]+$ ]] || {
  echo "error: V1_E15_WORKER_PROCESS_SUFFIX must match :[A-Za-z0-9_]+" >&2
  exit 2
}
mobench="${repo_root}/target/v1-benchmarks/toolchains/mobench/bin/cargo-mobench"
[[ -x "${mobench}" ]] || {
  echo "error: missing locked cargo-mobench; run bootstrap-mobench.sh" >&2
  exit 1
}

JAVA_HOME="${JAVA_HOME}" ANDROID_HOME="${ANDROID_HOME}" \
  ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT}" ANDROID_NDK_HOME="${ANDROID_NDK_HOME}" \
  "${mobench}" build --target android --release --yes --non-interactive \
  --output-dir "${output}"

android="${output}/android"
if [[ "${worker_process_suffix}" != ":mobench_worker" ]]; then
  escaped_suffix="${worker_process_suffix//\//\\/}"
  perl -pi -e \
    "s/:mobench_worker/${escaped_suffix}/g" \
    "${android}/app/src/main/AndroidManifest.xml" \
    "${android}/app/src/main/java/dev/world/benchmobile/MainActivity.kt"
fi
(
  cd "${android}"
  JAVA_HOME="${JAVA_HOME}" ANDROID_HOME="${ANDROID_HOME}" \
    ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT}" ./gradlew \
    assembleDebug assembleDebugAndroidTest --no-daemon
)

app="${android}/app/build/outputs/apk/debug/app-debug.apk"
test_app="${android}/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
shasum -a 256 "${app}" "${test_app}"
