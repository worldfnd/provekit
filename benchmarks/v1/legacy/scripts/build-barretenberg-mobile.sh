#!/usr/bin/env bash

set -euo pipefail

platform="${1:-}"
case "${platform}" in
  host | ios | android) ;;
  *)
    echo "usage: $0 <host|ios|android>" >&2
    exit 2
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
adapter_root="${benchmark_root}/barretenberg-mobile"
source_root="${repo_root}/target/v1-benchmarks/src/aztec-packages-v0.87.0"
# Keep the build directory revisioned. CMake caches toolchain-derived target
# properties before the first project() call, so reusing an older directory can
# silently retain an empty iOS architecture even after the toolchain is fixed.
build_revision="v3"
build_root="${repo_root}/target/v1-benchmarks/barretenberg-mobile/${platform}-${build_revision}"
expected_commit="9081b0ed38c43c120afb7c80f8f6cd418ca5ad70"

if [[ ! -d "${source_root}/.git" ]]; then
  mkdir -p "$(dirname "${source_root}")"
  git clone --filter=blob:none --no-checkout \
    https://github.com/AztecProtocol/aztec-packages.git "${source_root}"
fi

git -C "${source_root}" fetch --depth 1 origin "${expected_commit}"
git -C "${source_root}" checkout --detach "${expected_commit}"
actual_commit="$(git -C "${source_root}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
  echo "error: expected upstream ${expected_commit}, got ${actual_commit}" >&2
  exit 1
fi

generator="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
  generator="Ninja"
fi

cmake_args=(
  -S "${adapter_root}"
  -B "${build_root}"
  -G "${generator}"
  -DBB_V087_CPP_SOURCE="${source_root}/barretenberg/cpp"
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX="${build_root}/install"
)

case "${platform}" in
  ios)
    cmake_args+=(
      -DCMAKE_TOOLCHAIN_FILE="${adapter_root}/cmake/ios-arm64.cmake"
      -DCMAKE_OSX_SYSROOT=iphoneos
      -DCMAKE_OSX_ARCHITECTURES=arm64
      -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0
    )
    ;;
  android)
    if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
      default_ndk="/Users/dcbuilder/Library/Android/sdk/ndk/26.1.10909125"
      if [[ -d "${default_ndk}" ]]; then
        export ANDROID_NDK_HOME="${default_ndk}"
      else
        echo "error: set ANDROID_NDK_HOME to an installed Android NDK" >&2
        exit 1
      fi
    fi
    cmake_args+=(
      -DCMAKE_TOOLCHAIN_FILE="${adapter_root}/cmake/android-arm64.cmake"
    )
    ;;
esac

cmake "${cmake_args[@]}"

# The v0.87 ExternalProject asks the current default branch of the msgpack fork
# for an older, still-addressable commit. A plain clone no longer contains that
# object after an upstream history rewrite, while an explicit commit fetch does.
# Prime the generated ExternalProject checkout without modifying pinned source.
msgpack_prefix="${build_root}/_deps/msgpack-c"
msgpack_source="${msgpack_prefix}/src/msgpack-c"
msgpack_stamp="${msgpack_prefix}/src/msgpack-c-stamp"
msgpack_commit="5ee9a1c8c325658b29867829677c7eb79c433a98"
mkdir -p "$(dirname "${msgpack_source}")"
if [[ ! -d "${msgpack_source}/.git" ]]; then
  git clone --no-checkout https://github.com/AztecProtocol/msgpack-c.git \
    "${msgpack_source}"
fi
git -C "${msgpack_source}" fetch origin "${msgpack_commit}"
git -C "${msgpack_source}" checkout --detach "${msgpack_commit}"
if [[ -f "${msgpack_stamp}/msgpack-c-gitinfo.txt" ]]; then
  cp "${msgpack_stamp}/msgpack-c-gitinfo.txt" \
    "${msgpack_stamp}/msgpack-c-gitclone-lastrun.txt"
fi

cmake --build "${build_root}" --target barretenberg_v087_mobile --parallel

adapter_archive="${build_root}/libbarretenberg_v087_mobile.a"
upstream_archive="${build_root}/lib/libbarretenberg.a"
if [[ ! -f "${adapter_archive}" || ! -f "${upstream_archive}" ]]; then
  echo "error: build completed without both exact v0.87 archives" >&2
  exit 1
fi
mkdir -p "${build_root}/install/lib" "${build_root}/install/include"
cp "${adapter_archive}" "${build_root}/install/lib/"
cp "${upstream_archive}" "${build_root}/install/lib/"
cp "${adapter_root}/include/bb_v087_mobile.h" "${build_root}/install/include/"
library="${build_root}/install/lib/libbarretenberg_v087_mobile.a"

case "${platform}" in
  ios)
    lipo "${library}" -verify_arch arm64
    lipo "${build_root}/install/lib/libbarretenberg.a" -verify_arch arm64
    ;;
  android)
    ndk_bin="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    first_member="$("${ndk_bin}/llvm-ar" t "${library}" | head -n 1)"
    if ! "${ndk_bin}/llvm-ar" p "${library}" "${first_member}" |
      file - | grep -q "ELF 64-bit.*ARM aarch64"; then
      echo "error: Android archive does not contain AArch64 ELF objects" >&2
      exit 1
    fi
    ;;
esac

shasum -a 256 "${library}"
shasum -a 256 "${build_root}/install/lib/libbarretenberg.a"
