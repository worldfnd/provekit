#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
lock_file="${benchmark_root}/toolchains.lock.json"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"
source_root="${V1_PROVEKIT_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/provekit-v1-source}"
target_dir_override="${V1_PROVEKIT_WASM_TARGET_DIR:-}"
package_dir_override="${PROVEKIT_V1_WASM_PACKAGE_DIR:-}"
wasm_thread_request="${MOBENCH_WASM_THREADS:-single}"
wasm_variant="${PROVEKIT_V1_WASM_VARIANT:-}"
case "${wasm_thread_request}" in
  single|auto|threaded) ;;
  *)
    if [[ ! "${wasm_thread_request}" =~ ^[0-9]+$ ]] ||
      (( wasm_thread_request < 2 || wasm_thread_request > 32 )); then
      echo "error: MOBENCH_WASM_THREADS must be single, auto, threaded, or an integer from 2 to 32" >&2
      exit 2
    fi
    ;;
esac
if [[ -z "${wasm_variant}" ]]; then
  case "${wasm_thread_request}" in
    single) wasm_variant="single" ;;
    auto|threaded|[0-9]*) wasm_variant="threaded" ;;
  esac
fi
case "${wasm_variant}" in
  single|threaded) ;;
  *)
    echo "error: PROVEKIT_V1_WASM_VARIANT must be single or threaded" >&2
    exit 2
    ;;
esac
# The pinned V1 crate always emits wasm-bindgen-rayon hooks. The variant is a
# recorded campaign policy, not a scalar replacement of the proving artifact.
wasm_threads_available=true
if [[ -n "${target_dir_override}" ]]; then
  target_dir="${target_dir_override}"
elif [[ "${wasm_variant}" == "threaded" ]]; then
  target_dir="${repo_root}/target/v1-benchmarks/provekit-v1-wasm-target-threaded"
else
  target_dir="${repo_root}/target/v1-benchmarks/provekit-v1-wasm-target"
fi
if [[ -n "${package_dir_override}" ]]; then
  package_dir="${package_dir_override}"
elif [[ "${wasm_variant}" == "threaded" ]]; then
  package_dir="${benchmark_root}/wasm/v1-wasm-pkg-threaded"
else
  package_dir="${benchmark_root}/wasm/v1-wasm-pkg"
fi
artifact_dir="${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts"
input_dir="${repo_root}/target/v1-benchmarks/provekit-v1-inputs"
passport_p1_beta11="${repo_root}/target/v1-benchmarks/passport-p1-beta11"
oprf_o2_beta11="${repo_root}/target/v1-benchmarks/oprf-o2-beta11"

for command in cargo git jq; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

bash "${script_dir}/prepare-passport-p1-beta11.sh" >/dev/null
bash "${script_dir}/prepare-oprf-o2-beta11.sh" >/dev/null

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
  "${artifact_dir}/webauthn_assertion.json" \
  "${passport_p1_beta11}/target/passport_p1.json" \
  "${oprf_o2_beta11}/oprf/target/oprf.json"; do
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
    benchmarks/v1/noir/webauthn_assertion/target \
    benchmarks/v1/noir/passport_p1/target \
    target/v1-benchmarks
  rm -rf target/v1-benchmarks/noir-beta19-compat
  ln -s "${repo_root}/target/v1-benchmarks/noir-beta19-compat" \
    target/v1-benchmarks/noir-beta19-compat
  cp "${benchmark_root}/noir/webauthn_assertion/Nargo.toml" \
    benchmarks/v1/noir/webauthn_assertion/Nargo.toml
  rm -rf benchmarks/v1/noir/webauthn_assertion/src
  cp -R "${benchmark_root}/noir/webauthn_assertion/src" \
    benchmarks/v1/noir/webauthn_assertion/src
  cp "${benchmark_root}/noir/webauthn_assertion/Prover.toml" \
    benchmarks/v1/noir/webauthn_assertion/Prover.toml
  cp "${benchmark_root}/noir/webauthn_assertion/inputs.json" \
    benchmarks/v1/noir/webauthn_assertion/inputs.json
  cp "${artifact_dir}/complete_age_check.json" \
    noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json
  rm -rf benchmarks/v1/noir/oprf_o2_beta11
  cp -R "${oprf_o2_beta11}" benchmarks/v1/noir/oprf_o2_beta11
  cp "${artifact_dir}/webauthn_assertion.json" \
    benchmarks/v1/noir/webauthn_assertion/target/webauthn_assertion.json
  cp "${passport_p1_beta11}/Nargo.toml" benchmarks/v1/noir/passport_p1/Nargo.toml
  cp -R "${passport_p1_beta11}/src" benchmarks/v1/noir/passport_p1/
  cp -R "${passport_p1_beta11}/utils" benchmarks/v1/noir/passport_p1/
  cp "${passport_p1_beta11}/target/passport_p1.json" \
    benchmarks/v1/noir/passport_p1/target/passport_p1.json
  cp "${artifact_dir}/complete_age_check.Prover.toml" \
    "${input_dir}/passport_complete_age_check.Prover.toml"
  cp "${oprf_o2_beta11}/oprf/Prover.toml" "${input_dir}/oprf_taceo.Prover.toml"
  cp benchmarks/v1/noir/webauthn_assertion/Prover.toml \
    "${input_dir}/webauthn_assertion.Prover.toml"
  cp benchmarks/v1/noir/webauthn_assertion/inputs.json \
    "${input_dir}/webauthn_assertion.inputs.json"
  cp "${passport_p1_beta11}/Prover.toml" "${input_dir}/passport_p1.Prover.toml"
  cargo build --locked --release -p provekit-cli
  CARGO_TARGET_DIR="${target_dir}" \
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128,+relaxed-simd,-reference-types -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base" \
    cargo build -Z build-std=panic_abort,std --locked --release \
      --target wasm32-unknown-unknown -p provekit-wasm --no-default-features
)

cli="${source_root}/target/release/provekit-cli"
[[ -x "${cli}" ]] || { echo "error: missing ${cli}" >&2; exit 1; }
for spec in \
  "passport_complete_age_check|noir-examples/noir-passport-monolithic/complete_age_check|complete_age_check|passport_complete_age_check.Prover.toml" \
  "oprf_taceo|benchmarks/v1/noir/oprf_o2_beta11/oprf|oprf|oprf_taceo.Prover.toml" \
  "webauthn_assertion|benchmarks/v1/noir/webauthn_assertion|webauthn_assertion|webauthn_assertion.Prover.toml" \
  "passport_p1|benchmarks/v1/noir/passport_p1|passport_p1|passport_p1.Prover.toml"; do
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
printf '%s\n' \
  '{' \
  '  "name": "provekit-v1-wasm-local",' \
  '  "private": true,' \
  '  "type": "module",' \
  '  "module": "provekit_wasm.js",' \
  '  "main": "provekit_wasm.js",' \
  '  "sideEffects": true' \
  '}' >"${package_dir}/package.json"

wasm_sha256="$(shasum -a 256 "${package_dir}/provekit_wasm_bg.wasm" | awk '{print $1}')"
jq -n \
  --arg core_commit "${core_commit}" \
  --arg wasm_bindgen_version "$("${wasm_bindgen_bin}" --version | awk '{print $2}')" \
  --arg wasm_sha256 "${wasm_sha256}" \
  --arg wasm_variant "${wasm_variant}" \
  --arg wasm_thread_request "${wasm_thread_request}" \
  --argjson wasm_threads_available "${wasm_threads_available}" \
  '{schema_version:1,backend:("provekit_v1_wasm_" + $wasm_variant),core_commit:$core_commit,
    wasm_bindgen_version:$wasm_bindgen_version,wasm_sha256:$wasm_sha256,
    wasm_variant:$wasm_variant,wasm_thread_request:$wasm_thread_request,
    wasm_thread_mode:$wasm_variant,
    wasm_threads_available:$wasm_threads_available,shared_memory_build:true}' \
  >"${package_dir}/manifest.json"

echo "Prepared ${package_dir}"
