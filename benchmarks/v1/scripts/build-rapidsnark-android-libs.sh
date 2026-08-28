#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
source="${source_root}/rapidsnark"
output="${V1_RAPIDSNARK_ANDROID_LIB_DIR:-${repo_root}/target/v1-benchmarks/native-libs/rapidsnark/aarch64-linux-android}"
build_root="${V1_RAPIDSNARK_ANDROID_BUILD_ROOT:-${source}/build_prover_android}"
android_ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${HOME}/Library/Android/sdk/ndk/26.1.10909125}}"

for command in cmake git jq make shasum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
[[ -d "${android_ndk}/toolchains/llvm" ]] || {
  echo "error: Android NDK not found at ${android_ndk}" >&2
  exit 1
}

"${script_dir}/bootstrap-sources.sh" >/dev/null
expected_revision="$(
  jq -er '.sources[] | select(.name == "rapidsnark") | .revision' \
    "${benchmark_root}/sources.lock.json"
)"
[[ "$(git -C "${source}" rev-parse HEAD)" == "${expected_revision}" ]] || {
  echo "error: Rapidsnark checkout does not match sources.lock.json" >&2
  exit 1
}

export ANDROID_NDK="${android_ndk}"
if [[ ! -f "${source}/depends/gmp/package_android_arm64/lib/libgmp.a" ]]; then
  (
    cd "${source}"
    ./build_gmp.sh android
  )
fi

cmake \
  -S "${source}" \
  -B "${build_root}" \
  -DTARGET_PLATFORM=ANDROID \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${source}/package_android" \
  -DBUILD_TESTS=OFF \
  -DUSE_OPENMP=OFF
cmake --build "${build_root}" --target rapidsnarkStatic --parallel 8

mkdir -p "${output}"
for library in librapidsnark.a libfr.a libfq.a; do
  cp "${build_root}/src/${library}" "${output}/${library}"
done
cp "${source}/depends/gmp/package_android_arm64/lib/libgmp.a" "${output}/libgmp.a"
(
  cd "${output}"
  shasum -a 256 librapidsnark.a libfr.a libfq.a libgmp.a >SHA256SUMS
)

echo "${output}"
