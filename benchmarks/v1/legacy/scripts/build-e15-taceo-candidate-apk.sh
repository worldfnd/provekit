#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <package-suffix>" >&2; exit 2; }
suffix="$1"
[[ "${suffix}" =~ ^[a-z][a-z0-9]*$ ]] || { echo "invalid package suffix" >&2; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
android="${repo_root}/target/v1-benchmarks/taceo-e15-worldid/android"
output="${repo_root}/target/v1-benchmarks/taceo-e15-worldid/apks/${suffix}.apk"
java_home="${JAVA_HOME:-${HOME}/.local/share/mise/installs/java/temurin-21.0.11+10.0.LTS}"
android_home="${ANDROID_HOME:-${HOME}/Library/Android/sdk}"

mkdir -p "$(dirname "${output}")"
(cd "${android}" && JAVA_HOME="${java_home}" ANDROID_HOME="${android_home}" \
  ./gradlew assembleRelease "-PcandidateSuffix=.${suffix}" -x lintVitalRelease >/dev/null)
JAVA_HOME="${java_home}" "${android_home}/build-tools/36.0.0/apksigner" sign \
  --ks "${HOME}/.android/debug.keystore" --ks-pass pass:android --key-pass pass:android \
  --out "${output}" "${android}/app/build/outputs/apk/release/app-release-unsigned.apk"
shasum -a 256 "${output}"
