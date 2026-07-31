#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 ios" >&2
}

[[ $# -eq 1 && "$1" == "ios" ]] || {
  usage
  exit 2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
project="${repo_root}/target/v1-benchmarks/mopro/provekit-v1-mobile-adapters"
output="${repo_root}/target/v1-benchmarks/mopro-noir-ios"
srs="$("${script_dir}/prepare-noir-beta19-srs.sh")"

for command in bun cargo-mobench cp xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

"${script_dir}/prepare-mopro-native-adapters.sh"
function_list="$(cargo-mobench list --crate-path "${project}")"
for function in \
  bench_webauthn_barretenberg_prove \
  bench_webauthn_barretenberg_verify \
  bench_webauthn_barretenberg_proof_verify \
  bench_passport_barretenberg_prove \
  bench_passport_barretenberg_verify \
  bench_passport_barretenberg_proof_verify \
  bench_oprf_barretenberg_prove \
  bench_oprf_barretenberg_verify \
  bench_oprf_barretenberg_proof_verify; do
  grep -F "provekit_v1_mobile_adapters::${function}" \
    <<<"${function_list}" >/dev/null
done

cargo-mobench build \
  --target ios \
  --release \
  --ios-deployment-target 15.0 \
  --crate-path "${project}" \
  --output-dir "${output}" \
  --yes \
  --non-interactive \
  --progress

ios_project="${output}/ios/BenchRunner"
resources="${ios_project}/BenchRunner/Resources"
mkdir -p "${resources}"
bun "${script_dir}/patch-ios-runner-json.ts" \
  "${ios_project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
cp -c "${srs}" "${resources}/noir_beta19_campaign.dat" 2>/dev/null ||
  cp "${srs}" "${resources}/noir_beta19_campaign.dat"
(
  cd "${ios_project}"
  xcodegen generate
)
cargo-mobench package-ipa \
  --method adhoc \
  --crate-path "${project}" \
  --output-dir "${output}" \
  --yes \
  --non-interactive
"${script_dir}/preflight-ios15-charconv.sh" \
  "${output}/ios/BenchRunner.ipa"
cargo-mobench package-xcuitest \
  --crate-path "${project}" \
  --output-dir "${output}" \
  --yes \
  --non-interactive
"${script_dir}/patch-ios15-xcuitest-suite.sh" \
  "${output}/ios/BenchRunnerUITests.zip"

unzip -l "${output}/ios/BenchRunner.ipa" |
  grep -F "Payload/BenchRunner.app/noir_beta19_campaign.dat" >/dev/null
shasum -a 256 \
  "${output}/ios/BenchRunner.ipa" \
  "${output}/ios/BenchRunnerUITests.zip"
