#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
output="${repo_root}/target/v1-benchmarks/passport-p1-beta11"
nargo_home="${V1_BENCHMARK_NARGO_HOME:-${repo_root}/target/v1-benchmarks/nargo-home}"

rm -rf "${output}"
mkdir -p "${output}/src"
cp "${benchmark_root}/noir/passport_p1/src/main.nr" "${output}/src/main.nr"
cp "${benchmark_root}/noir/passport_p1/Prover.toml" "${output}/Prover.toml"
bun "${script_dir}/set-passport-p1-barrett.ts" "${output}/Prover.toml" 4
mkdir -p "${output}/utils/src"
cp -R "${repo_root}/noir-examples/noir-passport-monolithic/utils/utils/src/." \
  "${output}/utils/src/"
printf '%s\n' \
  '[package]' \
  'name = "utils"' \
  'type = "lib"' \
  'compiler_version = ">=1.0.0"' \
  '' \
  '[dependencies]' \
  'poseidon = { tag = "v0.1.1", git = "https://github.com/noir-lang/poseidon" }' \
  >"${output}/utils/Nargo.toml"

printf '%s\n' \
  '[package]' \
  'name = "passport_p1"' \
  'type = "bin"' \
  'compiler_version = ">=1.0.0"' \
  '' \
  '[dependencies]' \
  'poseidon = { tag = "v0.1.1", git = "https://github.com/noir-lang/poseidon" }' \
  'bignum = { tag = "v0.8.0", git = "https://github.com/noir-lang/noir-bignum" }' \
  'rsa = { tag = "v0.9.2", git = "https://github.com/zkpassport/noir_rsa" }' \
  'utils = { path = "utils" }' \
  'sha256 = { tag = "v0.3.0", git = "https://github.com/noir-lang/sha256" }' \
  >"${output}/Nargo.toml"

(
  cd "${output}"
  NARGO_HOME="${nargo_home}" nargo compile --force --skip-brillig-constraints-check
  NARGO_HOME="${nargo_home}" nargo execute witness --force --skip-brillig-constraints-check
)

jq -e '.noir_version | startswith("1.0.0-beta.11+")' \
  "${output}/target/passport_p1.json" >/dev/null
echo "${output}"
