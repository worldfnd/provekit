#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
source="${source_root}/rapidsnark"
output="${V1_RAPIDSNARK_IOS_LIB_DIR:-${repo_root}/target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-ios}"
sim_output="${V1_RAPIDSNARK_IOS_SIM_LIB_DIR:-${repo_root}/target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-ios-sim}"
build_root="${V1_RAPIDSNARK_IOS_BUILD_ROOT:-${repo_root}/target/v1-benchmarks/native-build/rapidsnark-ios15}"
build_simulator="${V1_RAPIDSNARK_BUILD_IOS_SIMULATOR:-0}"

case "${build_simulator}" in
  0 | 1) ;;
  *)
    echo "error: V1_RAPIDSNARK_BUILD_IOS_SIMULATOR must be 0 or 1" >&2
    exit 2
    ;;
esac

for command in cmake git lipo make shasum xcodebuild; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/bootstrap-sources.sh" >/dev/null
expected_revision="$(
  jq -er '.sources[] | select(.name == "rapidsnark") | .revision' \
    "${benchmark_root}/sources.lock.json"
)"
[[ "$(git -C "${source}" rev-parse HEAD)" == "${expected_revision}" ]] || {
  echo "error: Rapidsnark checkout does not match sources.lock.json" >&2
  exit 1
}

single_thread_patch="${benchmark_root}/rapidsnark-ios-single-thread.patch"
[[ -f "${single_thread_patch}" ]] || {
  echo "error: missing iOS single-thread patch ${single_thread_patch}" >&2
  exit 1
}
if git -C "${source}/depends/ffiasm" apply --check "${single_thread_patch}" 2>/dev/null; then
  git -C "${source}/depends/ffiasm" apply "${single_thread_patch}"
elif ! git -C "${source}/depends/ffiasm" apply --reverse --check \
  "${single_thread_patch}" 2>/dev/null; then
  echo "error: iOS single-thread patch does not apply cleanly" >&2
  exit 1
fi

low_memory_patch="${benchmark_root}/rapidsnark-ios-low-memory.patch"
[[ -f "${low_memory_patch}" ]] || {
  echo "error: missing iOS low-memory patch ${low_memory_patch}" >&2
  exit 1
}
if git -C "${source}" apply --check "${low_memory_patch}" 2>/dev/null; then
  git -C "${source}" apply "${low_memory_patch}"
elif ! git -C "${source}" apply --reverse --check \
  "${low_memory_patch}" 2>/dev/null; then
  echo "error: iOS low-memory patch does not apply cleanly" >&2
  exit 1
fi

if [[ ! -f "${source}/depends/gmp/package_ios_arm64/lib/libgmp.a" ]]; then
  (
    cd "${source}"
    ./build_gmp.sh ios
  )
fi
if [[ "${build_simulator}" == "1" &&
  ! -f "${source}/depends/gmp/package_iphone_simulator_arm64/lib/libgmp.a" ]]; then
  (
    cd "${source}"
    ./build_gmp.sh ios_simulator
  )
fi

cmake \
  -S "${source}" \
  -B "${build_root}" \
  -G Xcode \
  -DTARGET_PLATFORM=IOS \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DUSE_OPENMP=OFF \
  -DBUILD_TESTS=OFF
xcodebuild \
  -destination 'generic/platform=iOS' \
  -scheme rapidsnarkStatic \
  -project "${build_root}/rapidsnark.xcodeproj" \
  -configuration Release \
  CODE_SIGNING_ALLOWED=NO

mkdir -p "${output}"
for library in librapidsnark.a libfr.a libfq.a; do
  cp "${build_root}/src/Release-iphoneos/${library}" "${output}/${library}"
done
lipo \
  "${source}/depends/gmp/package_ios_arm64/lib/libgmp.a" \
  -thin arm64 \
  -output "${output}/libgmp.a"

(
  cd "${output}"
  shasum -a 256 librapidsnark.a libfr.a libfq.a libgmp.a >SHA256SUMS
)

echo "${output}"

if [[ "${build_simulator}" != "1" ]]; then
  exit 0
fi

(
  cd "${source}"
  make ios_simulator
)
sim_build="${source}/build_prover_ios_simulator/src/Debug-iphonesimulator"
mkdir -p "${sim_output}"
for library in librapidsnark.a libgmp.a; do
  lipo "${sim_build}/${library}" -thin arm64 -output "${sim_output}/${library}"
done
for library in libfr.a libfq.a; do
  cp "${sim_build}/${library}" "${sim_output}/${library}"
done
(
  cd "${sim_output}"
  shasum -a 256 librapidsnark.a libfr.a libfq.a libgmp.a >SHA256SUMS
)

echo "${sim_output}"
