#!/usr/bin/env bash

set -euo pipefail

readonly WARMUP=1
readonly SAMPLES=5

usage() {
  cat <<'EOF'
usage: run-reproducibility.sh [--stage] STAGE [options]

Stages:
  bootstrap  Verify locks, fetch pinned sources, and install pinned tools.
  prepare    Build circuits/adapters and freeze an artifact hash manifest.
  smoke      Require valid-proof acceptance and tampered-proof rejection.
  measure    Run Mac Chrome, physical E15, and BrowserStack iPhone lanes.
  export     Export raw evidence to the canonical sample-level CSV.
  all        Run bootstrap, prepare, smoke, measure, then export.

Options:
  --campaign ID                  Stable output directory name.
  --dry-run                      Print/log the complete non-secret command plan.
  --confirm-paid-browserstack    Explicitly authorize paid iPhone sessions.
  -h, --help                     Show this help.

Required environment for real device stages:
  V1_E15_MEASURE_SCRIPT          Optional physical-E15 ProveKit adapter override.
  V1_IOS_PREBUILT_MANIFEST      Immutable iPhone Mobench manifest.
  V1_E15_NATIVE_BACKEND_MANIFEST
                                Successful E15 Noir/Circom raw-evidence manifest.
  V1_E15_NATIVE_BACKEND_ATTEMPTS_JSON
                                Normalized successful E15 Noir/Circom rows.
  V1_E15_GAPS_JSON              E15 Noir/Circom gaps (defaults to campaign e15-native-gaps.json).
  V1_IOS_DEVICE                 Mobench device label (defaults to iPhone SE 2022-15).
  V1_IOS_OS_VERSION             Exact measured iOS version (defaults to iOS 15.4).
  V1_E15_CIRCOM_EVIDENCE        Retained E15 Arkworks build/qualification evidence.
  V1_E15_NOIR_EVIDENCE          Retained beta.19 Passport witness-failure evidence.
  ANDROID_SERIAL                Optional adb serial (required if >1 device).

The publication export reads the committed, hash-locked V1 evidence under
benchmarks/v1/semantic-parity-data/evidence/provekit-v1 and does not accept
browser or native timings from another campaign implicitly.

BrowserStack credentials must be exported as BROWSERSTACK_USERNAME and
BROWSERSTACK_ACCESS_KEY. They are never accepted as arguments or written to
the command log.
EOF
}

stage=""
campaign=""
dry_run=0
confirm_paid=0
while (($#)); do
  case "$1" in
    --stage) stage="${2:?missing --stage value}"; shift 2 ;;
    bootstrap | prepare | smoke | measure | export | all)
      [[ -z "${stage}" ]] || { echo "error: stage specified twice" >&2; exit 2; }
      stage="$1"; shift ;;
    --campaign) campaign="${2:?missing --campaign value}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --confirm-paid-browserstack) confirm_paid=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "${stage}" in
  bootstrap | prepare | smoke | measure | export | all) ;;
  *) echo "error: choose bootstrap, prepare, smoke, measure, export, or all" >&2; exit 2 ;;
esac
campaign="${campaign:-$(date -u '+%Y%m%dT%H%M%SZ')}"
[[ "${campaign}" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "error: campaign may contain only letters, digits, dot, underscore, and dash" >&2
  exit 2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
export PATH="${repo_root}/target/v1-benchmarks/toolchains/mobench/bin:${PATH}"
campaign_root="${V1_CAMPAIGN_ROOT:-${repo_root}/target/v1-benchmarks/reproduction/${campaign}}"
command_log="${campaign_root}/commands.log"
mkdir -p "${campaign_root}"
if [[ ! -e "${command_log}" ]]; then
  {
    printf '# ProveKit V1 reproducibility command log\n'
    printf '# campaign=%s\n' "${campaign}"
    printf '# source_sha=%s\n' "$(git -C "${repo_root}" rev-parse HEAD)"
    printf '# sampling=warmup:%s,measured:%s,sequential:true\n' "${WARMUP}" "${SAMPLES}"
  } >"${command_log}"
fi

log_command() {
  local cwd="$1"
  shift
  {
    printf 'cd %q &&' "${cwd}"
    printf ' %q' "$@"
    printf '\n'
  } | tee -a "${command_log}"
}

run_command() {
  local cwd="$1"
  shift
  log_command "${cwd}" "$@"
  ((dry_run)) || (cd "${cwd}" && "$@")
}

require_file() {
  local path="$1"
  [[ -f "${path}" ]] || { echo "error: missing ${path}" >&2; exit 1; }
}

verify_locks() {
  local locks=(
    "${benchmark_root}/toolchains.lock.json"
    "${benchmark_root}/sources.lock.json"
    "${benchmark_root}/circom/artifacts.lock.json"
    "${benchmark_root}/circom/trusted-setup.lock.json"
  )
  run_command "${repo_root}" jq -e 'type == "object"' "${locks[@]}"
  run_command "${repo_root}" git diff --check -- "${locks[@]}"
  run_command "${repo_root}" "${script_dir}/verify-circom-artifacts.sh"
}

run_bootstrap() {
  verify_locks
  local bootstrap
  for bootstrap in \
    bootstrap-sources.sh bootstrap-nargo.sh bootstrap-circom.sh \
    bootstrap-wasm-bindgen.sh bootstrap-mopro.sh bootstrap-w2c2.sh \
    bootstrap-barretenberg.sh bootstrap-mobench.sh bootstrap-android-java.sh; do
    run_command "${repo_root}" "${script_dir}/${bootstrap}"
  done
  run_command "${benchmark_root}/barretenberg" bun install --frozen-lockfile
  run_command "${benchmark_root}/wasm" bun install --frozen-lockfile
  run_command "${benchmark_root}/circom/web" bun install --frozen-lockfile
}

write_artifact_manifest() {
  local output="${campaign_root}/artifact-sha256.txt"
  local roots=(
    "${repo_root}/target/v1-benchmarks"
    "${benchmark_root}/circom/fixtures"
  )
  if ((dry_run)); then
    log_command "${repo_root}" find "${roots[@]}" -type f -exec shasum -a 256 '{}' +
    printf '# artifact hashes -> %s (sorted, paths relative to repository)\n' "${output}" |
      tee -a "${command_log}"
    return
  fi
  local temporary="${output}.tmp"
  (
    cd "${repo_root}"
    find "${roots[@]}" \
      -path "${repo_root}/target/v1-benchmarks/reproduction" -prune -o \
      -type f -exec shasum -a 256 '{}' + |
      sed "s#  ${repo_root}/#  #" |
      LC_ALL=C sort
  ) >"${temporary}"
  if [[ -e "${output}" ]]; then
    if ! cmp -s "${output}" "${temporary}"; then
      echo "error: prepared artifact hashes drifted from ${output}" >&2
      echo "       inspect ${temporary} before intentionally starting a new campaign" >&2
      exit 1
    fi
    unlink "${temporary}"
  else
    mv "${temporary}" "${output}"
  fi
}

run_prepare() {
  verify_locks
  ((dry_run)) || source "${script_dir}/android-env.sh"
  run_command "${repo_root}" "${script_dir}/compile-noir-workloads.sh"
  local workload
  for workload in webauthn_assertion passport_complete_age_check oprf_taceo; do
    run_command "${repo_root}" "${script_dir}/build-provekit-workload.sh" "${workload}"
  done
  run_command "${benchmark_root}/barretenberg" bun run build:web
  run_command "${repo_root}" "${script_dir}/prepare-webauthn-circom.sh" --witness
  run_command "${repo_root}" "${script_dir}/prepare-mopro-native-adapters.sh"
  run_command "${repo_root}" "${script_dir}/prepare-self-passport.sh"
  run_command "${repo_root}" "${script_dir}/generate-self-passport-witnesses.sh"
  local circuit
  for circuit in register_sha256_sha256_sha256_rsa_65537_4096 vc_and_disclose; do
    run_command "${repo_root}" "${script_dir}/prepare-self-groth16.sh" "${circuit}"
    run_command "${repo_root}" "${script_dir}/prepare-groth16-mobile-fixture.sh" "${circuit}"
  done
  run_command "${benchmark_root}/wasm" bun run build
  run_command "${benchmark_root}/circom/web" bun run build
  run_command "${repo_root}" "${script_dir}/prepare-circom-native-witnesses.sh"
  run_command "${repo_root}" "${script_dir}/prepare-rapidsnark-oprf-ios-prebuilt.sh"
  run_command "${repo_root}" \
    "${script_dir}/prepare-rapidsnark-passport-webauthn-ios-prebuilt.sh"
  write_artifact_manifest
}

run_smoke() {
  # Each called smoke is responsible for accepting a valid proof and rejecting
  # a tampered proof. A non-zero result prevents measurement.
  local workload
  for workload in webauthn passport oprf; do
    run_command "${benchmark_root}/barretenberg" bun run "smoke:${workload}"
  done
  run_command "${benchmark_root}/wasm" bun run smoke
  local browser_workload
  for browser_workload in passport webauthn oprf; do
    run_command "${benchmark_root}/circom/web" env "MOBENCH_WORKLOAD=${browser_workload}" \
      bun run smoke
  done
  run_command "${repo_root}" "${script_dir}/smoke-arkworks-oprf.sh"
  local circuit
  for circuit in register_sha256_sha256_sha256_rsa_65537_4096 vc_and_disclose; do
    run_command "${repo_root}" "${script_dir}/smoke-self-rapidsnark.sh" "${circuit}"
  done
}

capture_e15_identity() {
  local output="${campaign_root}/e15-adb-identity.json"
  local adb_command=(adb)
  [[ -z "${ANDROID_SERIAL:-}" ]] || adb_command+=(-s "${ANDROID_SERIAL}")
  if ((dry_run)); then
    run_command "${repo_root}" "${adb_command[@]}" get-state
    for prop in ro.product.manufacturer ro.product.model ro.build.version.release \
      ro.product.cpu.abilist ro.product.cpu.abi ro.product.cpu.abilist32 \
      ro.product.cpu.abilist64 ro.zygote; do
      run_command "${repo_root}" "${adb_command[@]}" shell getprop "${prop}"
    done
    printf '# E15 identity JSON -> %s\n' "${output}" | tee -a "${command_log}"
    return
  fi
  "${adb_command[@]}" get-state >/dev/null
  local manufacturer model os abilist abi abilist32 abilist64 zygote
  manufacturer="$("${adb_command[@]}" shell getprop ro.product.manufacturer | tr -d '\r')"
  model="$("${adb_command[@]}" shell getprop ro.product.model | tr -d '\r')"
  os="$("${adb_command[@]}" shell getprop ro.build.version.release | tr -d '\r')"
  abilist="$("${adb_command[@]}" shell getprop ro.product.cpu.abilist | tr -d '\r')"
  abi="$("${adb_command[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
  abilist32="$("${adb_command[@]}" shell getprop ro.product.cpu.abilist32 | tr -d '\r')"
  abilist64="$("${adb_command[@]}" shell getprop ro.product.cpu.abilist64 | tr -d '\r')"
  zygote="$("${adb_command[@]}" shell getprop ro.zygote | tr -d '\r')"
  jq -n --arg manufacturer "${manufacturer}" --arg model "${model}" --arg os "${os}" \
    --arg abilist "${abilist}" --arg abi "${abi}" --arg abilist32 "${abilist32}" \
    --arg abilist64 "${abilist64}" --arg zygote "${zygote}" \
    '{manufacturer:$manufacturer,model:$model,os:$os,abi:$abi,abilist:$abilist,
      abilist32:$abilist32,abilist64:$abilist64,zygote:$zygote}' >"${output}.tmp"
  mv "${output}.tmp" "${output}"
}

run_mac_chrome() {
  run_command "${repo_root}" env \
    "MAC_WASM_BENCHMARK_JSON=${campaign_root}/mac-chrome-wasm-benchmarks.json" \
    "MOBENCH_WARMUP=${WARMUP}" "MOBENCH_ITERATIONS=${SAMPLES}" \
    bun run "${script_dir}/run-mac-wasm-benchmarks.ts"
}

run_e15() {
  ((dry_run)) || source "${script_dir}/android-env.sh"
  capture_e15_identity
  local measure_script="${V1_E15_MEASURE_SCRIPT:-${script_dir}/run-e15-provekit.ts}"
  local normalizer="${benchmark_root}/data/normalize-e15-provekit.ts"
  local native_normalizer="${benchmark_root}/data/normalize-e15-native-backend.ts"
  local gap_generator="${benchmark_root}/data/generate-e15-native-gaps.ts"
  local output="${campaign_root}/e15"
  require_file "${measure_script}"
  require_file "${normalizer}"
  require_file "${gap_generator}"
  run_command "${repo_root}" "${measure_script}" \
    --campaign "${campaign}" --output "${output}" \
    --warmup "${WARMUP}" --samples "${SAMPLES}" --sequential
  run_command "${repo_root}" bun "${normalizer}" \
    "${output}/results.json" "${output}/attempts.json"
  local native_manifest="${V1_E15_NATIVE_BACKEND_MANIFEST:-}"
  if [[ -n "${native_manifest}" ]]; then
    require_file "${native_normalizer}"
    require_file "${native_manifest}"
    run_command "${repo_root}" bun "${native_normalizer}" \
      "${native_manifest}" "${campaign_root}/e15-native-backends.json"
  else
    local circom_evidence="${V1_E15_CIRCOM_EVIDENCE:-${campaign_root}/e15-circom-arkworks-armv7-build.log}"
    local noir_evidence="${V1_E15_NOIR_EVIDENCE:-${repo_root}/target/v1-benchmarks/reproduction/mac-chrome-20260729/raw/barretenberg-passport-build.log}"
    run_command "${repo_root}" env "CAMPAIGN_ID=${campaign}" bun "${gap_generator}" \
      "${campaign_root}/e15-adb-identity.json" "${campaign_root}/e15-native-gaps.json" \
      "$(git -C "${repo_root}" rev-parse HEAD)" "${circom_evidence}" "${noir_evidence}"
  fi
}

require_paid_access() {
  ((dry_run)) && return
  ((confirm_paid)) || {
    echo "error: iPhone measurement requires --confirm-paid-browserstack" >&2
    exit 1
  }
  [[ -n "${BROWSERSTACK_USERNAME:-}" && -n "${BROWSERSTACK_ACCESS_KEY:-}" ]] || {
    echo "error: export BrowserStack credentials locally" >&2
    exit 1
  }
  run_command "${repo_root}" "${script_dir}/preflight-browserstack-products.sh"
}

run_iphone() {
  require_paid_access
  local manifest="${V1_IOS_PREBUILT_MANIFEST:-}"
  if [[ -z "${manifest}" ]]; then
    ((dry_run)) && {
      printf '# required: V1_IOS_PREBUILT_MANIFEST=/absolute/path/to/manifest.json\n' |
        tee -a "${command_log}"
      return
    }
    echo "error: set V1_IOS_PREBUILT_MANIFEST" >&2
    exit 1
  fi
  require_file "${manifest}"
  local source_sha functions
  source_sha="$(jq -er '.source_sha' "${manifest}")"
  functions="$(jq -c '[.entries[].function]' "${manifest}")"
  jq -e --argjson warmup "${WARMUP}" --argjson samples "${SAMPLES}" \
    'all(.entries[]; .warmup == $warmup and .iterations == $samples)' "${manifest}" >/dev/null
  run_command "${repo_root}" cargo-mobench ci run-prebuilt \
    --manifest "${manifest}" --expected-source-sha "${source_sha}" \
    --expected-platform ios --expected-functions "${functions}" \
    --expected-iterations "${SAMPLES}" --expected-warmup "${WARMUP}" \
    --devices "iPhone SE 2022-15" --fetch \
    --fetch-output-dir "${campaign_root}/browserstack-ios" \
    --output-dir "${campaign_root}/native-ios" \
    --max-completion-timeout-secs 7200
}

run_measure() {
  run_mac_chrome
  run_e15
  run_iphone
}

run_export() {
  local exporter="${benchmark_root}/semantic-parity-data/export-v1.ts"
  local output="${benchmark_root}/semantic-parity-data/semantic-parity-samples.csv"
  require_file "${exporter}"
  # Publication export is sourced only from the committed, hash-locked V1
  # evidence. The device runs above still retain their raw reports in the
  # campaign directory for diagnosis and audit.
  run_command "${repo_root}" bun "${exporter}" "--output=${output}"
}

run_stage() {
  case "$1" in
    bootstrap) run_bootstrap ;;
    prepare) run_prepare ;;
    smoke) run_smoke ;;
    measure) run_measure ;;
    export) run_export ;;
  esac
}

if [[ "${stage}" == all ]]; then
  for selected in bootstrap prepare smoke measure export; do
    run_stage "${selected}"
  done
else
  run_stage "${stage}"
fi

printf '# finished_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >>"${command_log}"
echo "Command log: ${command_log}"
