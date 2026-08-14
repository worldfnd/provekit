#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <warm|cold>" >&2
}

[[ $# -eq 1 ]] || { usage; exit 2; }
mode="$1"
[[ "$mode" == warm || "$mode" == cold ]] || { usage; exit 2; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
crate="${benchmark_root}/circom/taceo-mobile"
source_prep="${benchmark_root}/circom/taceo-oprf/prepare-source.sh"
output="${repo_root}/target/v1-benchmarks/taceo-oprf-ios-build-${mode}"
prebuilt_root="${V1_TACEO_OPRF_IOS_PREBUILT_ROOT:-${repo_root}/target/v1-benchmarks/taceo-oprf-ios-prebuilt-${mode}}"
iterations="${V1_IOS_ITERATIONS:-5}"
warmup="${V1_IOS_WARMUP:-1}"
function="zk_mobile_bench::bench_taceo_oprf_input_to_proof"
cold_launches="${V1_IOS_COLD_LAUNCHES:-6}"
run_id="taceo-v021-oprf-ios-${mode}"
nonce="taceo-v021-oprf-ios-${mode}-nonce"
logical_session_id="taceo-v021-oprf-ios-${mode}"

if [[ "$mode" == cold ]]; then
  iterations=1
  warmup=0
  function="zk_mobile_bench::bench_taceo_oprf_input_to_proof_cold"
fi

for command in cargo-mobench cp jq shasum stat unzip xcodegen; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "error: $command is required" >&2
    exit 1
  }
done

"$source_prep" >/dev/null
cargo-mobench build \
  --target ios \
  --release \
  --ios-deployment-target 15.0 \
  --crate-path "$crate" \
  --output-dir "$output" \
  --yes \
  --non-interactive \
  --progress

project="${output}/ios/BenchRunner"
resources="${project}/BenchRunner/Resources"
mkdir -p "$resources" "${prebuilt_root}/entries/0000"

"$script_dir/patch-ios-runner-json.ts" \
  "${project}/BenchRunner/BenchRunnerFFI.swift" >/dev/null
jq -n \
  --arg function "$function" \
  --arg run_id "$run_id" \
  --arg nonce "$nonce" \
  --arg logical_session_id "$logical_session_id" \
  --argjson iterations "$iterations" \
  --argjson warmup "$warmup" \
  '{schema_version: "mobench.run/v2", run_id: $run_id, nonce: $nonce,
    logical_session_id: $logical_session_id, function_id: $function,
    producer: "ios-runner", function: $function, iterations: $iterations,
    warmup: $warmup}' \
  >"${resources}/bench_spec.json"
(
  cd "$project"
  xcodegen generate >/dev/null
)
cargo-mobench package-ipa \
  --method adhoc \
  --crate-path "$crate" \
  --output-dir "$output" \
  --yes \
  --non-interactive >/dev/null
if [[ "$mode" == cold ]]; then
  bun "$script_dir/patch-ios-cold-launches.ts" \
    "${project}/BenchRunnerUITests/BenchRunnerUITests.swift" \
    "$cold_launches" >/dev/null
  (
    cd "$project"
    xcodegen generate >/dev/null
  )
fi
cargo-mobench package-xcuitest \
  --crate-path "$crate" \
  --output-dir "$output" \
  --yes \
  --non-interactive >/dev/null
"$script_dir/patch-ios15-xcuitest-suite.sh" \
  "${output}/ios/BenchRunnerUITests.zip" >/dev/null

app="${prebuilt_root}/entries/0000/app.ipa"
suite="${prebuilt_root}/entries/0000/test-suite.zip"
cp -c "${output}/ios/BenchRunner.ipa" "$app" 2>/dev/null || cp "${output}/ios/BenchRunner.ipa" "$app"
cp -c "${output}/ios/BenchRunnerUITests.zip" "$suite" 2>/dev/null || cp "${output}/ios/BenchRunnerUITests.zip" "$suite"

unzip -p "$app" 'Payload/*.app/bench_spec.json' |
  jq -e --arg function "$function" --argjson iterations "$iterations" --argjson warmup "$warmup" \
    '.function == $function and .iterations == $iterations and .warmup == $warmup' >/dev/null

app_size="$(stat -f '%z' "$app")"
suite_size="$(stat -f '%z' "$suite")"
app_hash="$(shasum -a 256 "$app" | awk '{print $1}')"
suite_hash="$(shasum -a 256 "$suite" | awk '{print $1}')"
source_sha="$(git -C "$repo_root" rev-parse HEAD)"
jq -n \
  --arg source_sha "$source_sha" \
  --arg function "$function" \
  --arg mode "$mode" \
  --argjson iterations "$iterations" \
  --argjson warmup "$warmup" \
  --arg app_hash "$app_hash" \
  --arg suite_hash "$suite_hash" \
  --argjson app_size "$app_size" \
  --argjson suite_size "$suite_size" \
  --argjson cold_launches "$cold_launches" \
  '{
    schema: "mobench.prebuilt.v1",
    source_sha: $source_sha,
    platform: "ios",
    build_profile: "release",
    mobench_version: "0.2.0",
    abi: { benchmark: "mobench-bench-spec-v1", runner: "browserstack-xcuitest-v2" },
    entries: [{
      function: $function,
      iterations: $iterations,
      warmup: $warmup,
      completion_timeout_secs: 7200,
      artifacts: [
        { kind: "ios-app", path: "entries/0000/app.ipa", size: $app_size, sha256: $app_hash },
        { kind: "ios-test-suite", path: "entries/0000/test-suite.zip", size: $suite_size, sha256: $suite_hash }
      ]
    }]
  }' >"${prebuilt_root}/manifest.json"

jq -n \
  --arg mode "$mode" \
  --argjson cold_launches "$cold_launches" \
  '{
    schema: "provekit.taceo-oprf-source.v1",
    helpers_main: "8aacd73ed6ab0a2b9b2158e613acfa920860865a",
    circom_witness_rs_branch: "codex/remove-cxx-bridge-and-grep",
    circom_witness_rs: "e11206a9f453145dcd6b814523cbfba4f60cf5c6",
    circom: "2.2.2",
    mode: $mode,
    cold_launches: $cold_launches
  }' >"${prebuilt_root}.taceo-source.json"

shasum -a 256 "$app" "$suite" "${prebuilt_root}/manifest.json" "${prebuilt_root}.taceo-source.json"
echo "${prebuilt_root}/manifest.json"
