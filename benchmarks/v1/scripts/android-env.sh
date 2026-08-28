#!/usr/bin/env bash

# Source from Android build scripts. This resolves only locked,
# campaign-supported locations and never installs tools.

readonly V1_ANDROID_JAVA_VERSION="temurin-21.0.11+10.0.LTS"
readonly V1_ANDROID_NDK_VERSION="26.1.10909125"

if [[ -z "${JAVA_HOME:-}" ]]; then
  if command -v mise >/dev/null 2>&1; then
    java_home="$(mise where "java@${V1_ANDROID_JAVA_VERSION}" 2>/dev/null || true)"
    [[ -z "${java_home}" ]] || export JAVA_HOME="${java_home}"
    unset java_home
  elif [[ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]]; then
    export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  fi
fi

if [[ -z "${ANDROID_HOME:-}" ]]; then
  if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
    export ANDROID_HOME="${ANDROID_SDK_ROOT}"
  elif [[ -d "${HOME}/Library/Android/sdk" ]]; then
    export ANDROID_HOME="${HOME}/Library/Android/sdk"
  fi
fi
if [[ -n "${ANDROID_HOME:-}" ]]; then
  export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME}}"
  export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_HOME}/ndk/${V1_ANDROID_NDK_VERSION}}"
  export PATH="${ANDROID_HOME}/platform-tools:${PATH}"
fi

[[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] || {
  echo "error: install locked Java with: mise install java@${V1_ANDROID_JAVA_VERSION}" >&2
  return 1 2>/dev/null || exit 1
}
[[ "$("${JAVA_HOME}/bin/java" -version 2>&1 | head -1)" == *'"21.0.11"'* ]] || {
  echo "error: Android campaign builds require locked Java 21.0.11, found:" >&2
  "${JAVA_HOME}/bin/java" -version >&2
  return 1 2>/dev/null || exit 1
}
[[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME}/platforms/android-34" ]] || {
  echo "error: Android SDK platform 34 is required under ANDROID_HOME" >&2
  return 1 2>/dev/null || exit 1
}
[[ -d "${ANDROID_NDK_HOME}" ]] || {
  echo "error: Android NDK ${V1_ANDROID_NDK_VERSION} is required" >&2
  return 1 2>/dev/null || exit 1
}
