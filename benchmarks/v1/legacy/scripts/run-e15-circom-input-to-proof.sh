#!/usr/bin/env bash

set -euo pipefail

mode="${1:-all}"
[[ "${mode}" == "warm" || "${mode}" == "cold" || "${mode}" == "all" ]] || {
  echo "usage: $0 [warm|cold|all]" >&2
  exit 2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
adb="${ADB:-${HOME}/Library/Android/sdk/platform-tools/adb}"
serial="${ANDROID_SERIAL:-ZY32M6782K}"
evidence_root="${repo_root}/target/v1-benchmarks/input-to-proof/e15/publication"
activity="dev.world.provekitv1mobileadapters.MainActivity"
device_adb=("${adb}" -s "${serial}")

wait_for_boot() {
  "${device_adb[@]}" wait-for-device
  until [[ "$("${device_adb[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
    sleep 1
  done
  "${device_adb[@]}" shell input keyevent 82 >/dev/null
  sleep 60
}

valid_result() {
  local result="$1"
  local measured="$2"
  [[ -f "${result}" ]] &&
    jq -e --argjson measured "${measured}" \
      '.results | length == 1 and .[0].status == "ok" and (.[0].report.samples | length) == $measured' \
      "${result}" >/dev/null
}

run_attempt() {
  local name="$1"
  local workload="$2"
  local package_suffix="$3"
  local warmup="$4"
  local measured="$5"
  local timeout="$6"
  local output="$7"
  local apk="${repo_root}/target/v1-benchmarks/e15-circom-${name}-input-to-proof-build/android/app/build/outputs/apk/debug/app-debug.apk"
  local package_id="dev.world.provekitv1mobileadapters.${package_suffix}"

  if valid_result "${output}/results.json" "${measured}"; then
    echo "skip valid ${name} ${output##*/}"
    return
  fi
  mkdir -p "${output}"
  "${device_adb[@]}" reboot
  wait_for_boot
  ANDROID_SERIAL="${serial}" ADB="${adb}" bun "${script_dir}/run-e15-provekit.ts" \
    --output "${output}" \
    --campaign input-to-proof-e15-circom-rapidsnark \
    --apk "${apk}" \
    --package-id "${package_id}" \
    --activity-class "${activity}" \
    --worker-process-suffix :mobench_worker \
    --workloads "${workload}" \
    --warmup "${warmup}" \
    --samples "${measured}" \
    --timeout-seconds "${timeout}"
  valid_result "${output}/results.json" "${measured}" || {
    echo "invalid ${name} attempt retained at ${output}" >&2
    return 1
  }
}

run_workload() {
  local name="$1"
  local workload="$2"
  local package_suffix="$3"
  local timeout="$4"
  local run
  if [[ "${mode}" == "warm" || "${mode}" == "all" ]]; then
    run_attempt "${name}" "${workload}" "${package_suffix}" 1 5 "${timeout}" \
      "${evidence_root}/warm/circom-${name}"
  fi
  if [[ "${mode}" == "cold" || "${mode}" == "all" ]]; then
    for run in 0 1 2 3 4 5; do
      run_attempt "${name}" "${workload}" "${package_suffix}" 0 1 "${timeout}" \
        "${evidence_root}/cold/circom-${name}/run-${run}"
    done
  fi
}

run_workload oprf circom_oprf_input_to_proof rapidsnarkoprfinputtoproof 7200
run_workload passport-disclose circom_passport_disclose_input_to_proof rapidsnarkpassportdiscloseinputtoproof 7200
run_workload passport-register circom_passport_register_input_to_proof rapidsnarkpassportregisterinputtoproof 10800
run_workload passport-p1 circom_passport_p1_input_to_proof rapidsnarkpassportp1inputtoproof 10800
run_workload webauthn circom_webauthn_input_to_proof rapidsnarkwebauthninputtoproof 10800
