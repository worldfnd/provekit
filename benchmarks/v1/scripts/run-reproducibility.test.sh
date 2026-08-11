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
grep -q 'run-mac-input-to-proof.ts' "${measure_log}"
grep -q 'adb.*ro.product.cpu.abilist' "${measure_log}"
grep -q 'run-e15-provekit.ts' "${measure_log}"
grep -q 'normalize-e15-provekit.ts' "${measure_log}"
grep -q 'V1_IOS_PREBUILT_MANIFEST' "${measure_log}"
if grep -q 'BROWSERSTACK_ACCESS_KEY' "${measure_log}"; then
  echo "error: credential name leaked to command log" >&2
  exit 1
fi

grep -q 'input-to-proof-data/export.ts' "${temporary}/export/commands.log"
grep -q 'INPUT_TO_PROOF_EXPORT_TARGETS=mac_chrome\\,iphone_se_2022\\,motorola_e15' "${temporary}/export/commands.log"
grep -q 'INPUT_TO_PROOF_E15_RAW_ROOT=' "${temporary}/export/commands.log"
if grep -q 'BROWSERSTACK_ACCESS_KEY' "${temporary}/export/commands.log"; then
  echo "error: credential name leaked to export command log" >&2
  exit 1
fi

if V1_CAMPAIGN_ROOT="${temporary}/bad" \
  "${runner}" obsolete --campaign test --dry-run >/dev/null 2>&1; then
  echo "error: obsolete stage unexpectedly accepted" >&2
  exit 1
fi

echo "run-reproducibility tests passed"
