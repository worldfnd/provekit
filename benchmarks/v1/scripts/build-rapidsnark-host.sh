#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
rapidsnark="${repo_root}/target/v1-benchmarks/sources/rapidsnark"

"${script_dir}/bootstrap-sources.sh"

case "$(uname -m)-$(uname -s)" in
  arm64-Darwin)
    gmp_target="macos_arm64"
    gmp_package="package_macos_arm64"
    make_target="macos_arm64"
    prover_package="package_macos_arm64"
    ;;
  x86_64-Darwin | x86_64-Linux)
    gmp_target="host"
    gmp_package="package"
    make_target="host"
    prover_package="package"
    ;;
  aarch64-Linux | arm64-Linux)
    gmp_target="aarch64"
    gmp_package="package_aarch64"
    make_target="host_arm64"
    prover_package="package_arm64"
    ;;
  *)
    echo "error: unsupported Rapidsnark host $(uname -m)-$(uname -s)" >&2
    exit 1
    ;;
esac

for command in cmake make m4 nasm pkg-config; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

for library in gmp libsodium; do
  if ! pkg-config --exists "${library}"; then
    echo "error: pkg-config could not find ${library}" >&2
    exit 1
  fi
done

prover="${rapidsnark}/${prover_package}/bin/prover"
if [[ -x "${prover}" ]]; then
  echo "Pinned Rapidsnark host prover is ready at ${prover}"
  exit 0
fi

(
  cd "${rapidsnark}"
  if [[ ! -d "depends/gmp/${gmp_package}" ]]; then
    ./build_gmp.sh "${gmp_target}"
  fi
  make "${make_target}"
)

echo "Built pinned Rapidsnark host prover at ${prover}"
