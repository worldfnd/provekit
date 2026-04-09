#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <platform> <results-dir> <browserstack-dir>" >&2
  exit 2
fi

platform="$1"
results_dir="$2"
browserstack_dir="$3"
failed=0
device_summaries_count=0
csv_data_rows=0
recovered_payloads=0
spec_matches_requested=1
requested_spec='{}'
actual_specs='[]'

error() {
  echo "::error::$1"
  failed=1
}

warn() {
  echo "::warning::$1"
}

first_match() {
  local search_root="$1"
  local name="$2"
  find "$search_root" -type f -name "$name" 2>/dev/null | sort | head -1
}

has_valid_bench_payload() {
  local report_path="$1"
  jq -e '
    def valid_result:
      ((.function? // .spec?.name?) != null)
      and (
        ((.samples? // []) | length) > 0
        or (.mean_ns? != null)
        or (.median_ns? != null)
        or (.p95_ns? != null)
        or (.min_ns? != null)
        or (.max_ns? != null)
      );

    if type == "array" then
      any(.[]; valid_result)
    else
      valid_result
    end
  ' "$report_path" >/dev/null 2>&1
}

echo "Inspecting ${platform} results"
echo "  results_dir=${results_dir}"
echo "  browserstack_dir=${browserstack_dir}"

summary_json="$(first_match "$results_dir" summary.json)"
results_csv="$(first_match "$results_dir" results.csv)"

if [ -n "$summary_json" ]; then
  device_summaries_count="$(
    jq -r '
      [
        ((.device_summaries // []) | length),
        ((.summary?.device_summaries // []) | length)
      ] | max
    ' "$summary_json"
  )"
  requested_spec="$(
    jq -c '
      {
        function: (.spec.function // ""),
        iterations: (.spec.iterations // -1),
        warmup: (.spec.warmup // -1)
      }
    ' "$summary_json"
  )"
  actual_specs="$(
    jq -c '
      [
        (.benchmark_results // {})
        | to_entries[]?
        | .value[]?
        | {
            function: (.function // .spec?.name // ""),
            iterations: (.spec?.iterations // .iterations // -1),
            warmup: (.spec?.warmup // .warmup // -1)
          }
      ] | unique
    ' "$summary_json"
  )"
  if ! jq -e '
    def requested:
      {
        function: (.spec.function // ""),
        iterations: (.spec.iterations // -1),
        warmup: (.spec.warmup // -1)
      };
    def actual_specs:
      [
        (.benchmark_results // {})
        | to_entries[]?
        | .value[]?
        | {
            function: (.function // .spec?.name // ""),
            iterations: (.spec?.iterations // .iterations // -1),
            warmup: (.spec?.warmup // .warmup // -1)
          }
      ] | unique;
    requested as $requested
    | actual_specs as $actual
    | ($actual | length) > 0
      and all($actual[]; . == $requested)
  ' "$summary_json" >/dev/null; then
    spec_matches_requested=0
  fi
  echo "  summary_json=${summary_json}"
  echo "  summary_device_summaries=${device_summaries_count}"
  echo "  requested_spec=${requested_spec}"
  echo "  actual_specs=${actual_specs}"
else
  warn "${platform}: summary.json was not found under ${results_dir}"
fi

if [ -n "$results_csv" ]; then
  csv_line_count="$(wc -l < "$results_csv" | tr -d ' ')"
  if [ "$csv_line_count" -gt 0 ]; then
    csv_data_rows=$((csv_line_count - 1))
  fi
  echo "  results_csv=${results_csv}"
  echo "  csv_data_rows=${csv_data_rows}"
else
  warn "${platform}: results.csv was not found under ${results_dir}"
fi

build_found=0
has_incomplete_browserstack_state=0

while IFS= read -r build_json; do
  [ -n "$build_json" ] || continue
  build_found=1
  build_dir="$(dirname "$build_json")"
  build_id="$(jq -r '.build_id // .id // "unknown"' "$build_json")"
  build_status="$(jq -r '.status // "unknown"' "$build_json")"
  build_status_lc="$(printf '%s' "$build_status" | tr '[:upper:]' '[:lower:]')"

  echo "  browserstack_build id=${build_id} status=${build_status} dir=${build_dir}"

  case "$build_status_lc" in
    running|failed|error|timeout|timedout)
      has_incomplete_browserstack_state=1
      ;;
  esac

  while IFS=$'\t' read -r session_id device_name session_status; do
    [ -n "$session_id" ] || continue

    session_dir="${build_dir}/session-${session_id}"
    session_json="${session_dir}/session.json"
    testcase_status='{}'
    testcase_problem_count=0
    payload_found=false

    if [ -f "$session_json" ]; then
      testcase_status="$(jq -c '.testcases.status // {}' "$session_json")"
      testcase_problem_count="$(
        jq -r '(
          (.testcases.status.running // 0)
          + (.testcases.status.failed // 0)
          + (.testcases.status.error // 0)
          + (.testcases.status.timedout // 0)
        )' "$session_json"
      )"
    fi

    bench_report="${session_dir}/bench-report.json"
    if [ -f "$bench_report" ] && has_valid_bench_payload "$bench_report"; then
      payload_found=true
      recovered_payloads=$((recovered_payloads + 1))
    fi

    echo "  browserstack_session device=${device_name} session=${session_id} status=${session_status} testcase_status=${testcase_status} payload=${payload_found}"

    session_status_lc="$(printf '%s' "$session_status" | tr '[:upper:]' '[:lower:]')"
    case "$session_status_lc" in
      running|failed|error|timeout|timedout)
        has_incomplete_browserstack_state=1
        ;;
    esac

    if [ "$testcase_problem_count" -gt 0 ]; then
      has_incomplete_browserstack_state=1
    fi
  done < <(
    jq -r '
      (.devices // [])[]? as $device
      | ($device.device // $device.name // "unknown") as $device_name
      | ($device.os_version // "") as $os_version
      | ($device.sessions // [])[]?
      | [
          (.id // .session_id // .sessionId // ""),
          ($device_name + (if $os_version == "" then "" else "-" + $os_version end)),
          (.status // "unknown")
        ]
      | @tsv
    ' "$build_json"
  )
done < <(find "$browserstack_dir" -type f -name build.json 2>/dev/null | sort)

echo "  recovered_benchmark_payloads=${recovered_payloads}"

if [ -z "$summary_json" ]; then
  error "${platform}: summary.json was not produced"
fi

if [ "$device_summaries_count" -le 0 ]; then
  error "${platform}: summary.json has no device_summaries"
fi

if [ "$spec_matches_requested" -eq 0 ]; then
  error "${platform}: benchmark results do not match requested spec ${requested_spec}; actual ${actual_specs}"
fi

if [ -z "$results_csv" ]; then
  error "${platform}: results.csv was not produced"
fi

if [ "$csv_data_rows" -le 0 ]; then
  error "${platform}: results.csv has no benchmark data rows"
fi

if [ "$build_found" -eq 0 ]; then
  error "${platform}: no BrowserStack build.json artifacts were fetched"
fi

if [ "$has_incomplete_browserstack_state" -ne 0 ]; then
  error "${platform}: BrowserStack build/session state is incomplete or failed"
fi

if [ "$recovered_payloads" -le 0 ]; then
  warn "${platform}: no bench-report.json payloads were recovered from fetched BrowserStack artifacts"
fi

exit "$failed"
