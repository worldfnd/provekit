#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
adb="${ADB:-${HOME}/Library/Android/sdk/platform-tools/adb}"
serial="${ANDROID_SERIAL:-ZY32M6782K}"
apk="${repo_root}/target/v1-benchmarks/e15-noir-barretenberg-armv7-build/android/app/build/outputs/apk/debug/app-debug.apk"
output_root="${repo_root}/target/v1-benchmarks/input-to-proof/e15/publication/cold"
package_id="dev.world.provekitv1mobileadapters.paritypassportnoirarmv7"
activity="dev.world.provekitv1mobileadapters.MainActivity"

device_adb=("${adb}" -s "${serial}")

wait_for_boot() {
  "${device_adb[@]}" wait-for-device
  until [[ "$("${device_adb[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
    sleep 1
  done
  "${device_adb[@]}" shell input keyevent 82 >/dev/null
  # Android's native bad-process quarantine can survive boot completion.
  sleep 60
}

valid_result() {
  local result="$1"
  [[ -f "${result}" ]] &&
    jq -e '.results | length == 1 and .[0].status == "ok" and (.[0].report.samples | length) == 1' \
      "${result}" >/dev/null
}

run_series() {
  local name="$1"
  local workload="$2"
  local timeout="$3"
  local run output
  for run in 0 1 2 3 4 5; do
    output="${output_root}/barretenberg-${name}/run-${run}"
    if valid_result "${output}/results.json"; then
      echo "skip valid ${name} run-${run}"
      continue
    fi
    mkdir -p "${output}"
    "${device_adb[@]}" reboot
    wait_for_boot
    ANDROID_SERIAL="${serial}" ADB="${adb}" bun "${script_dir}/run-e15-provekit.ts" \
      --output "${output}" \
      --campaign input-to-proof-e15-barretenberg-cold \
      --apk "${apk}" \
      --package-id "${package_id}" \
      --activity-class "${activity}" \
      --worker-process-suffix :mobench_worker \
      --workloads "${workload}" \
      --warmup 0 \
      --samples 1 \
      --timeout-seconds "${timeout}"
    valid_result "${output}/results.json" || {
      echo "invalid ${name} run-${run}; retained at ${output}" >&2
      return 1
    }
  done
}

run_series oprf bb_oprf_input_to_proof 3600
run_series webauthn bb_webauthn_input_to_proof 3600
run_series passport-p1 bb_passport_p1_input_to_proof 5400
run_series passport bb_passport_input_to_proof 7200
