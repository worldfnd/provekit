#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_checkout="${V1_OPRF_COMPAT_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/oprf-nr-beta19}"
output="${repo_root}/target/v1-benchmarks/oprf-o2-beta11"
nargo_home="${V1_BENCHMARK_NARGO_HOME:-${repo_root}/target/v1-benchmarks/nargo-home}"
nargo_bin="$(V1_NARGO_LOCK_KEY=noir_provekit "${script_dir}/bootstrap-nargo.sh")"
expected_revision="7831dca615db55147c60f49415af6e86730df090"

actual_revision="$(git -C "${source_checkout}" rev-parse HEAD)"
[[ "${actual_revision}" == "${expected_revision}" ]] || {
  echo "error: OPRF compatibility source is ${actual_revision}, expected ${expected_revision}" >&2
  exit 1
}
[[ -z "$(git -C "${source_checkout}" status --short)" ]] || {
  echo "error: OPRF compatibility source checkout is dirty" >&2
  exit 1
}

rm -rf "${output}"
mkdir -p "${output}/oprf/src" "${output}/babyjubjub" "${output}/eddsa_poseidon2"
cp -R "${repo_root}/noir-examples/oprf/src/." "${output}/oprf/src/"
cp "${repo_root}/noir-examples/oprf/Prover.toml" "${output}/oprf/Prover.toml"
cp -R "${source_checkout}/babyjubjub/src" "${output}/babyjubjub/"
cp -R "${repo_root}/noir-examples/eddsa_poseidon2/src" "${output}/eddsa_poseidon2/"

printf '%s\n' \
  '[package]' \
  'name = "babyjubjub"' \
  'type = "lib"' \
  'authors = [""]' \
  '' \
  '[dependencies]' \
  'poseidon2 = { tag = "v0.6.0", git = "https://github.com/TaceoLabs/noir-poseidon", directory = "poseidon2" }' \
  >"${output}/babyjubjub/Nargo.toml"

printf '%s\n' \
  '[package]' \
  'name = "eddsa_poseidon2"' \
  'type = "lib"' \
  'authors = [""]' \
  '' \
  '[dependencies]' \
  'poseidon2 = { tag = "v0.5.0-beta.0", git = "https://github.com/TaceoLabs/noir-poseidon", directory = "poseidon2" }' \
  'babyjubjub = { path = "../babyjubjub" }' \
  >"${output}/eddsa_poseidon2/Nargo.toml"

printf '%s\n' \
  '[package]' \
  'name = "oprf"' \
  'type = "bin"' \
  'authors = [""]' \
  '' \
  '[dependencies]' \
  'poseidon2 = { tag = "v0.5.0-beta.0", git = "https://github.com/TaceoLabs/noir-poseidon", directory = "poseidon2" }' \
  'babyjubjub = { path = "../babyjubjub" }' \
  'eddsa_poseidon2 = { path = "../eddsa_poseidon2" }' \
  'binary_merkle_root = { git = "https://github.com/privacy-scaling-explorations/zk-kit.noir", tag = "binary-merkle-root-v0.0.1", directory = "packages/binary-merkle-root" }' \
  >"${output}/oprf/Nargo.toml"

(
  cd "${output}/oprf"
  NARGO_HOME="${nargo_home}" "${nargo_bin}" compile --force --skip-brillig-constraints-check
  NARGO_HOME="${nargo_home}" "${nargo_bin}" execute witness --force --skip-brillig-constraints-check
)

jq -e '.noir_version | startswith("1.0.0-beta.11+")' \
  "${output}/oprf/target/oprf.json" >/dev/null
echo "${output}"
