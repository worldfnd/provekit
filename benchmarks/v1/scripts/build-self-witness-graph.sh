#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <register_sha256_sha256_sha256_rsa_65537_4096|vc_and_disclose>" >&2
  exit 1
fi

name="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
self_root="${source_root}/self"
witness_source="${source_root}/circom-witness-rs"
build_root="${repo_root}/target/v1-benchmarks/circom-witness-builds/${name}"
crate_root="${build_root}/circom-witness-rs"
include_root="${build_root}/circom-include"
graph_root="${V1_BENCHMARK_WITNESS_GRAPH_ROOT:-${repo_root}/target/v1-benchmarks/circom-witness-graphs}/self"
circom_bin="$("${script_dir}/bootstrap-circom.sh")"
lock_file="${benchmark_root}/circom/circom-witness-rs.Cargo.lock"

case "${name}" in
  register_sha256_sha256_sha256_rsa_65537_4096)
    circuit="${self_root}/circuits/circuits/register/instances/${name}.circom"
    fixture="${benchmark_root}/circom/fixtures/self/${name}.json"
    witness="${repo_root}/target/v1-benchmarks/circom-witnesses/self/${name}/wasm.wtns"
    ;;
  vc_and_disclose)
    circuit="${self_root}/circuits/circuits/disclose/${name}.circom"
    fixture="${benchmark_root}/circom/fixtures/self/${name}.json"
    witness="${repo_root}/target/v1-benchmarks/circom-witnesses/self/${name}/wasm.wtns"
    ;;
  *)
    echo "error: unsupported Self circuit ${name}" >&2
    exit 1
    ;;
esac

for command in cargo jq perl rsync; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ ! -f "${witness}" ]] ||
  [[ ! -f "$(dirname "${witness}")/result.json" ]] ||
  ! jq -e '.byte_identical == true and .constraints_checked == true' \
    "$(dirname "${witness}")/result.json" >/dev/null; then
  "${script_dir}/generate-self-passport-witnesses.sh"
fi

mkdir -p "${crate_root}" "${graph_root}"
rsync -a --delete \
  --exclude target \
  "${witness_source}/" \
  "${crate_root}/"
cp "${benchmark_root}/circom/circom-witness-graph-main.rs" "${crate_root}/src/main.rs"
cp "${lock_file}" "${crate_root}/Cargo.lock"
perl -0777 -pi -e '$_ .= "\n[workspace]\n"' "${crate_root}/Cargo.toml"

# Upstream graph generation hard-codes O2. Self's distributed circuit build is
# O1, so keep the graph's witness-to-signal mapping aligned with the R1CS.
perl -pi -e 's/\.arg\("--O2"\)/.arg("--O1")/' "${crate_root}/build.rs"
if grep -q 'arg("--O2")' "${crate_root}/build.rs"; then
  echo "error: failed to align circom-witness-rs graph generation with Self O1" >&2
  exit 1
fi

mkdir -p "${include_root}"
find "${include_root}" -mindepth 1 -maxdepth 1 -delete
link_include_directory() {
  find "$1" -mindepth 1 -maxdepth 1 -print0 |
    while IFS= read -r -d '' path; do
      destination="${include_root}/$(basename "${path}")"
      if [[ ! -e "${destination}" ]]; then
        ln -s "${path}" "${destination}"
      fi
    done
}
link_include_directory "${self_root}/circuits/node_modules"
link_include_directory "${self_root}/circuits/node_modules/circomlib/circuits"
link_include_directory "${self_root}/circuits/node_modules/@openpassport/zk-email-circuits"
link_include_directory \
  "${self_root}/circuits/node_modules/@zk-kit/binary-merkle-root.circom/src"

(
  cd "${crate_root}"
  PATH="$(dirname "${circom_bin}"):${PATH}" \
  CXXFLAGS="-O0 -g0" \
  WITNESS_CPP="${circuit}" \
  CIRCOM_LIBRARY_PATH="${include_root}" \
    cargo run --locked --release --features build-witness -- generate

  cargo run --locked --release --features build-witness -- \
    check \
    "${crate_root}/graph.bin" \
    "${fixture}" \
    "${witness}"
)

cp "${crate_root}/graph.bin" "${graph_root}/${name}.bin"
echo "Built and reference-checked ${graph_root}/${name}.bin"
