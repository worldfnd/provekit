#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: prepare-webauthn-circom.sh [--witness] [--setup]

Compiles the pinned privacy-ethereum/webauth-circom assertion circuit and
builds its native witness generator. --witness also generates and checks the
fixture WTNS. --setup additionally creates and verifies a benchmark-only
Groth16 zkey; set V1_WEBAUTHN_PTAU to a power-22-or-larger PTAU first.
EOF
}

build_witness=false
build_setup=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
  --witness)
    build_witness=true
    ;;
  --setup)
    build_witness=true
    build_setup=true
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 1
    ;;
  esac
  shift
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/sources.lock.json"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
source_dir="${source_root}/webauth-circom"
output_root="${V1_WEBAUTHN_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom/webauthn}"
groth16_root="${V1_WEBAUTHN_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16/webauthn}"
expected_revision="$(
  jq -er '.sources[] | select(.name == "webauth-circom") | .revision' "${lock_file}"
)"

for command in bun git jq node openssl stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

snarkjs_node_options="${V1_SNARKJS_NODE_OPTIONS:---max-old-space-size=32768}"
run_snarkjs() {
  NODE_OPTIONS="${snarkjs_node_options}" \
    node "${source_dir}/node_modules/snarkjs/build/cli.cjs" "$@"
}

"${script_dir}/bootstrap-sources.sh" >/dev/null
actual_revision="$(git -C "${source_dir}" rev-parse HEAD)"
if [[ "${actual_revision}" != "${expected_revision}" ]]; then
  echo "error: webauth-circom is at ${actual_revision}, expected ${expected_revision}" >&2
  exit 1
fi

if [[ ! -d "${source_dir}/node_modules/circomlib" ]]; then
  (
    cd "${source_dir}"
    bun install --frozen-lockfile
  )
fi

circom="$("${script_dir}/bootstrap-circom.sh")"
circuit="${source_dir}/scripts/webauthn_default.circom"
fixture="${source_dir}/scripts/input_webauthn_default.json"
r1cs="${output_root}/webauthn_default.r1cs"
sym="${output_root}/webauthn_default.sym"
wasm="${output_root}/webauthn_default_js/webauthn_default.wasm"
cpp_dir="${output_root}/webauthn_default_cpp"
dat="${cpp_dir}/webauthn_default.dat"
wtns="${output_root}/fixture.wtns"
compile_log="${output_root}/compile.log"
manifest="${output_root}/manifest.json"

mkdir -p "${output_root}"
if [[ ! -f "${r1cs}" || ! -f "${sym}" || ! -f "${wasm}" || ! -f "${dat}" ]]; then
  "${circom}" "${circuit}" \
    --r1cs \
    --wasm \
    --sym \
    --c \
    -l "${source_dir}/node_modules" \
    -o "${output_root}" 2>&1 | tee "${compile_log}"
fi

if [[ "${build_witness}" == "true" ]]; then
  node "${output_root}/webauthn_default_js/generate_witness.js" \
    "${wasm}" \
    "${fixture}" \
    "${wtns}"
  run_snarkjs wtns check "${r1cs}" "${wtns}"
fi

zkey="${groth16_root}/webauthn_default_benchmark.zkey"
verification_key="${groth16_root}/verification_key.json"
if [[ "${build_setup}" == "true" ]]; then
  ptau="${V1_WEBAUTHN_PTAU:-$("${script_dir}/bootstrap-ptau.sh" 22)}"
  if [[ ! -f "${ptau}" ]]; then
    echo "error: V1_WEBAUTHN_PTAU does not exist: ${ptau}" >&2
    exit 1
  fi

  mkdir -p "${groth16_root}"
  if [[ ! -f "${zkey}" ]]; then
    partial_zkey="${zkey}.partial.$$"
    trap 'rm -f "${partial_zkey:-}"' EXIT
    run_snarkjs groth16 setup "${r1cs}" "${ptau}" "${partial_zkey}"
    mv "${partial_zkey}" "${zkey}"
    trap - EXIT
  fi
  run_snarkjs zkey verify "${r1cs}" "${ptau}" "${zkey}"
  run_snarkjs zkey export verificationkey "${zkey}" "${verification_key}"
fi

stat_size() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

artifact_json() {
  local path="$1"
  jq -n \
    --arg path "${path#"${repo_root}/"}" \
    --arg sha256 "$(openssl dgst -sha256 "${path}" | awk '{print tolower($NF)}')" \
    --argjson size "$(stat_size "${path}")" \
    '{path: $path, size_bytes: $size, sha256: $sha256}'
}

artifacts="$(
  artifact_json "${r1cs}"
  artifact_json "${sym}"
  artifact_json "${wasm}"
  artifact_json "${dat}"
  if [[ -f "${wtns}" ]]; then artifact_json "${wtns}"; fi
  if [[ -f "${zkey}" && -f "${verification_key}" ]]; then
    artifact_json "${zkey}"
    artifact_json "${verification_key}"
  fi
)"

jq -s \
  --arg source_revision "${actual_revision}" \
  --arg circuit "${circuit#"${repo_root}/"}" \
  --arg fixture "${fixture#"${repo_root}/"}" \
  --arg circom_version "$("${circom}" --version | tr -d '\r')" \
  '{
    schema_version: 1,
    workload: "webauthn_assertion",
    statement: {
      validates: [
        "webauthn.get type",
        "challenge inclusion in clientDataJSON",
        "authenticatorData plus clientDataJSON hash construction",
        "P-256 signature"
      ],
      does_not_constrain: ["RP ID hash", "origin", "UP flag", "UV flag"],
      comparable_to_world_id_noir_ownership: false
    },
    source_revision: $source_revision,
    circuit: $circuit,
    fixture: $fixture,
    circom_version: $circom_version,
    expected_non_linear_constraints: 2812892,
    artifacts: .
  }' <<<"${artifacts}" >"${manifest}"

echo "Prepared Circom WebAuthn artifacts under ${output_root}"
echo "Manifest: ${manifest}"
