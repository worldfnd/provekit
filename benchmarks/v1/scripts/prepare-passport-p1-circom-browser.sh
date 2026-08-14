#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
web_root="${benchmark_root}/circom/web"
circom_root="${V1_BENCHMARK_CIRCOM_ROOT:-${repo_root}/target/v1-benchmarks/circom}/passport_p1"
groth16_root="${V1_BENCHMARK_GROTH16_ROOT:-${repo_root}/target/v1-benchmarks/groth16}/passport_p1"
output_root="${P1_CIRCOM_BROWSER_ROOT:-${repo_root}/target/v1-benchmarks/circom-browser-p1}"
fixture_root="${output_root}/fixtures"
dist="${output_root}/dist"

for command in cp jq shasum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/prepare-passport-p1-groth16.sh"

for source in \
  "${circom_root}/passport_p1_js/passport_p1.wasm" \
  "${groth16_root}/passport_p1_final.zkey" \
  "${groth16_root}/verification_key.json" \
  "${benchmark_root}/circom/fixtures/passport_p1/input.json" \
  "${groth16_root}/ceremony.json"; do
  [[ -f "${source}" ]] || {
    echo "error: missing P1 browser artifact ${source}" >&2
    exit 1
  }
done

mkdir -p "${fixture_root}"
cp -c "${circom_root}/passport_p1_js/passport_p1.wasm" "${fixture_root}/passport_p1.wasm" 2>/dev/null ||
  cp "${circom_root}/passport_p1_js/passport_p1.wasm" "${fixture_root}/passport_p1.wasm"
cp -c "${groth16_root}/passport_p1_final.zkey" "${fixture_root}/passport_p1_final.zkey" 2>/dev/null ||
  cp "${groth16_root}/passport_p1_final.zkey" "${fixture_root}/passport_p1_final.zkey"
cp "${groth16_root}/verification_key.json" "${fixture_root}/passport_p1.vkey.json"
cp "${benchmark_root}/circom/fixtures/passport_p1/input.json" "${fixture_root}/passport_p1.input.json"

wasm_sha="$(shasum -a 256 "${fixture_root}/passport_p1.wasm" | awk '{print $1}')"
zkey_sha="$(shasum -a 256 "${fixture_root}/passport_p1_final.zkey" | awk '{print $1}')"
vkey_sha="$(shasum -a 256 "${fixture_root}/passport_p1.vkey.json" | awk '{print $1}')"
input_sha="$(shasum -a 256 "${fixture_root}/passport_p1.input.json" | awk '{print $1}')"
source_commit="$(git -C "${repo_root}" rev-parse HEAD)"

jq -n \
  --arg source_commit "${source_commit}" \
  --arg wasm_sha "${wasm_sha}" \
  --arg zkey_sha "${zkey_sha}" \
  --arg vkey_sha "${vkey_sha}" \
  --arg input_sha "${input_sha}" \
  '{schema_version: 1, fixtures: {passport: [{circuit: "passport_p1", variant: "p1_matched_monolithic_rsa4096", profile: "P1", wasm: "passport_p1.wasm", zkey: "passport_p1_final.zkey", verification_key: "passport_p1.vkey.json", input: "passport_p1.input.json", circuit_commit: $source_commit, semantic_equivalence: "p1-matched-monolithic", ceremony: {production_safe: false, final_zkey_sha256: $zkey_sha}, artifact_hashes: {wasm: $wasm_sha, final_zkey: $zkey_sha, verification_key: $vkey_sha, input: $input_sha}}], webauthn: [], oprf: []}}' \
  >"${fixture_root}/manifest.json"

CIRCOM_BROWSER_FIXTURE_ROOT="${fixture_root}" \
CIRCOM_BROWSER_DIST="${dist}" \
CIRCOM_BROWSER_PROFILE=p1 \
  bash "${web_root}/build.sh"

echo "prepared P1 browser bundle at ${dist}"
