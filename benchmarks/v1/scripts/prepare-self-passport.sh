#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
self_root="${source_root}/self"
output_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/self"
fixture_root="${benchmark_root}/circom/fixtures/self"
source_revision="$(jq -r '.sources[] | select(.name == "self") | .revision' "${benchmark_root}/sources.lock.json")"

for command in bun jq make node pkg-config; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ "$(node --version)" != v22.* ]]; then
  echo "error: Self pins Node >=22 <23, found $(node --version)" >&2
  exit 1
fi

for library in gmp nlohmann_json; do
  if ! pkg-config --exists "${library}"; then
    echo "error: pkg-config could not find ${library}" >&2
    exit 1
  fi
done

"${script_dir}/bootstrap-sources.sh" >/dev/null
circom_bin="$("${script_dir}/bootstrap-circom.sh")"

if [[ ! -f "${self_root}/node_modules/.pnpm/lock.yaml" ]]; then
  if ! command -v corepack >/dev/null 2>&1; then
    echo "error: corepack is required to install Self's pinned pnpm graph" >&2
    exit 1
  fi
  (
    cd "${self_root}"
    corepack pnpm install --frozen-lockfile
  )
fi

(
  cd "${self_root}"
  bun run circuits/scripts/link-circom-deps.cjs
)

SELF_SOURCE_ROOT="${self_root}" \
SELF_SOURCE_REVISION="${source_revision}" \
SELF_FIXTURE_OUTPUT_ROOT="${fixture_root}" \
SELF_FIXTURE_MODE="${SELF_FIXTURE_MODE:-check}" \
  bun run "${benchmark_root}/circom/generate-self-passport-fixtures.ts"

include_paths=(
  "${self_root}/circuits/node_modules"
  "${self_root}/circuits/node_modules/circomlib/circuits"
  "${self_root}/circuits/node_modules/@openpassport/zk-email-circuits"
  "${self_root}/circuits/node_modules/@zk-kit/binary-merkle-root.circom/src"
)

compile_circuit() {
  local name="$1"
  local source="$2"
  local destination="${output_root}/${name}"
  local r1cs="${destination}/${name}.r1cs"
  local wasm="${destination}/${name}_js/${name}.wasm"
  local cpp="${destination}/${name}_cpp/${name}"
  local cpp_makefile="${destination}/${name}_cpp/Makefile"
  local compile_all=0

  if [[ "${V1_BENCHMARK_REBUILD_CIRCOM:-0}" == "1" || ! -f "${r1cs}" || ! -f "${wasm}" ]]; then
    compile_all=1
    mkdir -p "${destination}"
    include_args=()
    for path in "${include_paths[@]}"; do
      include_args+=(-l "${path}")
    done
    "${circom_bin}" "${source}" \
      --O1 \
      --r1cs \
      --wasm \
      --c \
      --no_asm \
      --sym \
      "${include_args[@]}" \
      -o "${destination}"
  fi

  if [[ "${compile_all}" == "0" ]] && grep -q 'fr_asm' "${cpp_makefile}"; then
    find "${destination}/${name}_cpp" -maxdepth 1 \
      \( -name '*.o' -o -name "${name}" \) \
      -type f \
      -delete
    include_args=()
    for path in "${include_paths[@]}"; do
      include_args+=(-l "${path}")
    done
    "${circom_bin}" "${source}" \
      --O1 \
      --c \
      --no_asm \
      "${include_args[@]}" \
      -o "${destination}"
  fi

  if [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] &&
    grep -q 'uint64_t' "${destination}/${name}_cpp/fr.hpp"; then
    if ! command -v perl >/dev/null 2>&1; then
      echo "error: perl is required for Circom's Apple Silicon GMP compatibility rewrite" >&2
      exit 1
    fi
    perl -pi -e 's/\buint64_t\b/mp_limb_t/g' \
      "${destination}/${name}_cpp/fr.cpp" \
      "${destination}/${name}_cpp/fr.hpp"
    find "${destination}/${name}_cpp" -maxdepth 1 -name '*.o' -type f -delete
  fi

  if [[ ! -x "${cpp}" ]]; then
    make -C "${destination}/${name}_cpp" \
      CC="g++ $(pkg-config --libs-only-L gmp)" \
      CFLAGS="-std=c++11 -O3 -I. $(pkg-config --cflags gmp nlohmann_json)"
  fi

  echo "ready ${name}"
}

compile_circuit \
  "register_sha256_sha256_sha256_rsa_65537_4096" \
  "${self_root}/circuits/circuits/register/instances/register_sha256_sha256_sha256_rsa_65537_4096.circom"
compile_circuit \
  "vc_and_disclose" \
  "${self_root}/circuits/circuits/disclose/vc_and_disclose.circom"

echo "Self passport circuits and deterministic fixtures are ready."
