#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
self_root="${source_root}/self"
output_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/passport_p1"
source="${benchmark_root}/circom/passport_p1/passport_p1.circom"

for command in bun jq make node pkg-config; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

if [[ "$(node --version)" != v22.* ]]; then
  echo "error: Self pins Node >=22 <23, found $(node --version)" >&2
  exit 1
fi
for library in gmp nlohmann_json; do
  pkg-config --exists "${library}" || {
    echo "error: pkg-config could not find ${library}" >&2
    exit 1
  }
done

"${script_dir}/bootstrap-sources.sh" >/dev/null
circom_bin="$("${script_dir}/bootstrap-circom.sh")"

if [[ ! -f "${self_root}/node_modules/.pnpm/lock.yaml" ]]; then
  command -v corepack >/dev/null 2>&1 || {
    echo "error: corepack is required to install Self's pinned pnpm graph" >&2
    exit 1
  }
  (
    cd "${self_root}"
    corepack pnpm install --frozen-lockfile
  )
fi
(
  cd "${self_root}"
  bun run circuits/scripts/link-circom-deps.cjs
)

P1_FIXTURE_MODE="${P1_FIXTURE_MODE:-check}" \
  bun run "${benchmark_root}/circom/passport_p1/generate-fixture.ts"

include_paths=(
  "${self_root}/circuits/node_modules"
  "${self_root}/circuits/node_modules/circomlib/circuits"
  "${self_root}/circuits/node_modules/@openpassport/zk-email-circuits"
  "${self_root}/circuits/node_modules/@zk-kit/binary-merkle-root.circom/src"
)
include_args=()
for path in "${include_paths[@]}"; do
  include_args+=(-l "${path}")
done

r1cs="${output_root}/passport_p1.r1cs"
wasm="${output_root}/passport_p1_js/passport_p1.wasm"
cpp="${output_root}/passport_p1_cpp/passport_p1"
if [[ "${V1_BENCHMARK_REBUILD_CIRCOM:-0}" == "1" || ! -f "${r1cs}" || ! -f "${wasm}" ]]; then
  mkdir -p "${output_root}"
  "${circom_bin}" "${source}" \
    --O1 --r1cs --wasm --c --no_asm --sym \
    "${include_args[@]}" \
    -o "${output_root}"
fi

if [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] &&
  grep -q 'uint64_t' "${output_root}/passport_p1_cpp/fr.hpp"; then
  perl -pi -e 's/\buint64_t\b/mp_limb_t/g' \
    "${output_root}/passport_p1_cpp/fr.cpp" \
    "${output_root}/passport_p1_cpp/fr.hpp"
  find "${output_root}/passport_p1_cpp" -maxdepth 1 -name '*.o' -type f -delete
fi

if [[ ! -x "${cpp}" ]]; then
  make -C "${output_root}/passport_p1_cpp" \
    CC="g++ $(pkg-config --libs-only-L gmp)" \
    CFLAGS="-std=c++11 -O3 -I. $(pkg-config --cflags gmp nlohmann_json)"
fi

echo "ready P1 Circom artifacts at ${output_root}"
