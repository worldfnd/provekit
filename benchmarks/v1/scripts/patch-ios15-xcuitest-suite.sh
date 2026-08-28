#!/usr/bin/env bash

set -euo pipefail

suite="${1:?usage: patch-ios15-xcuitest-suite.sh <BenchRunnerUITests.zip>}"
testing_interop="$(
  xcrun --sdk iphoneos --show-sdk-platform-path
)/Developer/usr/lib/lib_TestingInterop.dylib"
testing_foundation="$(
  xcrun --sdk iphoneos --show-sdk-platform-path
)/Developer/Library/Frameworks/_Testing_Foundation.framework"

for command in codesign ditto find xcrun; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

[[ -f "${suite}" ]] || {
  echo "error: XCUITest suite not found: ${suite}" >&2
  exit 1
}
[[ -f "${testing_interop}" ]] || {
  echo "error: Xcode Testing interop library not found: ${testing_interop}" >&2
  exit 1
}
[[ -d "${testing_foundation}" ]] || {
  echo "error: Xcode Testing Foundation framework not found: ${testing_foundation}" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/provekit-xcuitest.XXXXXX")"
cleanup() {
  rm -rf "${work}"
}
trap cleanup EXIT

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

next="${work}/BenchRunnerUITests.zip"
ditto -c -k --sequesterRsrc --keepParent "${runner}" "${next}"
mv "${next}" "${suite}"
echo "Patched ${suite} for Xcode 26 runners on iOS 15"
