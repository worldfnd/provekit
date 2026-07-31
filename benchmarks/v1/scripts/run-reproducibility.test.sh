#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runner="${script_dir}/run-reproducibility.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

bash -n "${runner}"

for stage in bootstrap prepare smoke measure export all; do
  output="${temporary}/${stage}.out"
  V1_CAMPAIGN_ROOT="${temporary}/${stage}" \
    "${runner}" "${stage}" --campaign test --dry-run >"${output}"
  grep -q 'Command log:' "${output}"
  test -s "${temporary}/${stage}/commands.log"
done

measure_log="${temporary}/measure/commands.log"
grep -q 'MAC_WASM_BENCHMARK_JSON=' "${measure_log}"
grep -q 'adb.*ro.product.cpu.abilist' "${measure_log}"
grep -q 'run-e15-provekit.ts' "${measure_log}"
grep -q 'normalize-e15-provekit.ts' "${measure_log}"
grep -q 'V1_IOS_PREBUILT_MANIFEST' "${measure_log}"
if grep -q 'BROWSERSTACK_ACCESS_KEY' "${measure_log}"; then
  echo "error: credential name leaked to command log" >&2
  exit 1
fi

native_manifest="${temporary}/e15-native-backends.manifest.json"
touch "${native_manifest}"
V1_CAMPAIGN_ROOT="${temporary}/native-backends" \
  V1_E15_NATIVE_BACKEND_MANIFEST="${native_manifest}" \
  "${runner}" measure --campaign test --dry-run \
  >"${temporary}/native-backends.out"
grep -q 'normalize-e15-native-backend.ts' \
  "${temporary}/native-backends/commands.log"
if grep -q 'generate-e15-native-gaps.ts' \
  "${temporary}/native-backends/commands.log"; then
  echo "error: successful E15 native backend manifest was replaced with gaps" >&2
  exit 1
fi

native_attempts="${temporary}/e15-native-backends.json"
V1_CAMPAIGN_ROOT="${temporary}/native-export" \
  V1_E15_NATIVE_BACKEND_ATTEMPTS_JSON="${native_attempts}" \
  "${runner}" export --campaign test --dry-run \
  >"${temporary}/native-export.out"
grep -q "${native_attempts}" "${temporary}/native-export/commands.log"
if grep -q 'e15-native-gaps.json' \
  "${temporary}/native-export/commands.log"; then
  echo "error: export merged stale E15 gaps with successful native backend rows" >&2
  exit 1
fi

grep -q 'normalize-ios-prebuilt.ts' "${temporary}/export/commands.log"
grep -q 'CAMPAIGN_ID=test' "${temporary}/export/commands.log"
grep -q 'iOS\\ 15.4' "${temporary}/export/commands.log"
grep -q 'merge-attempts.ts' "${temporary}/export/commands.log"
grep -q 'export-benchmark-csv.ts' "${temporary}/export/commands.log"

if V1_CAMPAIGN_ROOT="${temporary}/bad" \
  "${runner}" obsolete --campaign test --dry-run >/dev/null 2>&1; then
  echo "error: obsolete stage unexpectedly accepted" >&2
  exit 1
fi

echo "run-reproducibility tests passed"
