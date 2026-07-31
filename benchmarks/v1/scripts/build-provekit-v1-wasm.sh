#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"
source_root="${V1_PROVEKIT_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/provekit-v1-source}"
target_dir="${V1_PROVEKIT_WASM_TARGET_DIR:-${repo_root}/target/v1-benchmarks/provekit-v1-wasm-target}"
package_dir="${benchmark_root}/wasm/v1-wasm-pkg"
artifact_dir="${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts"
input_dir="${repo_root}/target/v1-benchmarks/provekit-v1-inputs"

for command in cargo git jq; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

core_commit="$(jq -er '.provekit_v1.core_commit' "${lock_file}")"
if ! git -C "${repo_root}" cat-file -e "${core_commit}^{commit}"; then
  echo "error: ProveKit V1 core commit ${core_commit} is not present" >&2
  exit 1
fi
if [[ -e "${source_root}" ]]; then
  git -C "${source_root}" rev-parse --verify HEAD >/dev/null 2>&1 || {
    echo "error: ${source_root} exists but is not a Git worktree" >&2
    exit 1
  }
  actual_commit="$(git -C "${source_root}" rev-parse HEAD)"
  [[ "${actual_commit}" == "${core_commit}" ]] || {
    echo "error: ${source_root} is ${actual_commit}, expected ${core_commit}" >&2
    exit 1
  }
else
  git -C "${repo_root}" worktree add --detach "${source_root}" "${core_commit}"
fi

for required in \
  "${artifact_dir}/complete_age_check.json" \
  "${artifact_dir}/oprf.json" \
  "${artifact_dir}/webauthn_assertion.json"; do
  [[ -s "${required}" ]] || {
    echo "error: missing frozen beta.11 artifact ${required}; run prepare-provekit-beta11-artifacts.sh" >&2
    exit 1
  }
done

mkdir -p "${input_dir}"

wasm_bindgen_bin="${tool_root}/wasm-bindgen-cli-$(jq -er '.wasm_bindgen_cli.version' "${lock_file}")/bin/wasm-bindgen"
if [[ ! -x "${wasm_bindgen_bin}" ]]; then
  wasm_bindgen_bin="$(${script_dir}/bootstrap-wasm-bindgen.sh)"
fi

mkdir -p "${target_dir}"
echo "Building ProveKit V1 WASM from ${core_commit}"
(
  cd "${source_root}"
  mkdir -p \
    noir-examples/noir-passport-monolithic/complete_age_check/target \
    noir-examples/oprf/target \
    benchmarks/v1/noir/webauthn_assertion/target
  cp "${artifact_dir}/complete_age_check.json" \
    noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json
  cp "${artifact_dir}/oprf.json" noir-examples/oprf/target/oprf.json
  cp "${artifact_dir}/webauthn_assertion.json" \
    benchmarks/v1/noir/webauthn_assertion/target/webauthn_assertion.json
  cp "${artifact_dir}/complete_age_check.Prover.toml" \
    "${input_dir}/passport_complete_age_check.Prover.toml"
  cp noir-examples/oprf/Prover.toml "${input_dir}/oprf_taceo.Prover.toml"
  cp benchmarks/v1/noir/webauthn_assertion/Prover.toml \
    "${input_dir}/webauthn_assertion.Prover.toml"
  cp benchmarks/v1/noir/webauthn_assertion/inputs.json \
    "${input_dir}/webauthn_assertion.inputs.json"
  cargo build --locked --release -p provekit-cli
  CARGO_TARGET_DIR="${target_dir}" \
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-C target-feature=+simd128,+bulk-memory,+mutable-globals,-reference-types" \
    cargo build --locked --release --target wasm32-unknown-unknown -p provekit-wasm --no-default-features
)

cli="${source_root}/target/release/provekit-cli"
[[ -x "${cli}" ]] || { echo "error: missing ${cli}" >&2; exit 1; }
for spec in \
  "passport_complete_age_check|noir-examples/noir-passport-monolithic/complete_age_check|complete_age_check|complete_age_check.Prover.toml" \
  "oprf_taceo|noir-examples/oprf|oprf|oprf_taceo.Prover.toml" \
  "webauthn_assertion|benchmarks/v1/noir/webauthn_assertion|webauthn_assertion|webauthn_assertion.Prover.toml"; do
  IFS='|' read -r workload circuit_dir program input_name <<<"${spec}"
  out_dir="${repo_root}/target/v1-benchmarks/artifacts/${workload}"
  mkdir -p "${out_dir}"
  "${cli}" prepare \
    --target-dir "${source_root}/${circuit_dir}/target" \
    --skip-brillig-constraints-check --force \
    --pkp "${out_dir}/${workload}.pkp" \
    --pkv "${out_dir}/${workload}.pkv" \
    "${source_root}/${circuit_dir}"
  "${cli}" prove \
    --prover "${out_dir}/${workload}.pkp" \
    --input "${input_dir}/${input_name}" \
    --out "${out_dir}/${workload}.np"
  "${cli}" verify \
    --verifier "${out_dir}/${workload}.pkv" \
    --proof "${out_dir}/${workload}.np"
done

rm -rf "${package_dir}"
mkdir -p "${package_dir}"
"${wasm_bindgen_bin}" \
  --target web \
  --out-dir "${package_dir}" \
  "${target_dir}/wasm32-unknown-unknown/release/provekit_wasm.wasm"

wasm_sha256="$(shasum -a 256 "${package_dir}/provekit_wasm_bg.wasm" | awk '{print $1}')"
jq -n \
  --arg core_commit "${core_commit}" \
  --arg wasm_bindgen_version "$("${wasm_bindgen_bin}" --version | awk '{print $2}')" \
  --arg wasm_sha256 "${wasm_sha256}" \
  '{schema_version:1,backend:"provekit_v1_wasm_single",core_commit:$core_commit,
    wasm_bindgen_version:$wasm_bindgen_version,wasm_sha256:$wasm_sha256}' \
  >"${package_dir}/manifest.json"

echo "Prepared ${package_dir}"
