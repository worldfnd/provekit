#!/usr/bin/env bash

set -euo pipefail

prebuilt_root="${1:?usage: patch-xcuitest-testing-interop.sh <prebuilt-root>}"
testing_interop="$(
  xcrun --sdk iphoneos --show-sdk-platform-path
)/Developer/usr/lib/lib_TestingInterop.dylib"
testing_foundation="$(
  xcrun --sdk iphoneos --show-sdk-platform-path
)/Developer/Library/Frameworks/_Testing_Foundation.framework"

for command in codesign ditto jq shasum stat xcrun; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

[[ -f "${testing_interop}" ]] || {
  echo "error: Xcode Testing interop library not found at ${testing_interop}" >&2
  exit 1
}
[[ -d "${testing_foundation}" ]] || {
  echo "error: Xcode Testing Foundation framework not found at ${testing_foundation}" >&2
  exit 1
}

while IFS= read -r manifest; do
  manifest_root="$(dirname "${manifest}")"
  relative_suite="$(
    jq -er '.entries[].artifacts[] | select(.kind == "ios-test-suite") | .path' "${manifest}"
  )"
  suite="${manifest_root}/${relative_suite}"
  work="$(mktemp -d)"
  trap 'rm -rf "${work}"' EXIT
  ditto -x -k "${suite}" "${work}/unpacked"
  runner="$(find "${work}/unpacked" -maxdepth 1 -type d -name '*UITests-Runner.app' -print -quit)"
  [[ -n "${runner}" ]] || {
    echo "error: XCUITest runner app not found in ${suite}" >&2
    exit 1
  }
  frameworks="${runner}/Frameworks"
  mkdir -p "${frameworks}"
  cp "${testing_interop}" "${frameworks}/lib_TestingInterop.dylib"
  codesign --force --sign - "${frameworks}/lib_TestingInterop.dylib"
  cp -R "${testing_foundation}" "${frameworks}/_Testing_Foundation.framework"
  codesign --force --deep --sign - "${frameworks}/_Testing_Foundation.framework"
  ditto -c -k --sequesterRsrc --keepParent "${runner}" "${work}/test-suite.zip"

  suite_bytes="$(stat -f '%z' "${work}/test-suite.zip")"
  suite_sha256="$(shasum -a 256 "${work}/test-suite.zip" | awk '{print $1}')"
  manifest_next="$(mktemp "${manifest}.next.XXXXXX")"
  jq \
    --arg artifact_path "${relative_suite}" \
    --argjson artifact_size "${suite_bytes}" \
    --arg artifact_sha256 "${suite_sha256}" \
    '(.entries[].artifacts[] | select(.path == $artifact_path)) |=
      (.size = $artifact_size | .sha256 = $artifact_sha256)' \
    "${manifest}" >"${manifest_next}"

  mv "${work}/test-suite.zip" "${suite}"
  mv "${manifest_next}" "${manifest}"
  rm -rf "${work}"
  trap - EXIT
  echo "Patched ${suite}"
done < <(find "${prebuilt_root}" -name manifest.json -type f -print | sort)
