#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 10 ] || [ "$#" -gt 11 ]; then
  echo "usage: $0 <platform> <functions> <iterations> <warmup> <crate-path> <release-flag> <devices-csv> <fetch-timeout-secs> <output-dir> <fetch-output-dir> [ios-completion-timeout-secs]" >&2
  exit 2
fi

platform="$1"
functions_arg="$2"
iterations="$3"
warmup="$4"
crate_path="$5"
release_flag="$6"
device_specs_csv="$7"
fetch_timeout_secs="$8"
output_dir="$9"
fetch_output_dir="${10}"
ios_completion_timeout_secs="${11:-}"

max_attempts="${MOBENCH_FETCH_MAX_ATTEMPTS:-2}"
retry_sleep_secs="${MOBENCH_FETCH_RETRY_SLEEP_SECS:-60}"
log_dir="target/mobench/retry-logs/${platform}"
last_status=0
retryable=0

mkdir -p "$log_dir"

is_transient_fetch_failure() {
  local attempt_log="$1"
  local json_path

  if grep -Eiq 'BrowserStack API .*status 5[0-9]{2}|This website is under heavy load|fetch did not recover any benchmark payloads' "$attempt_log"; then
    return 0
  fi

  while IFS= read -r -d '' json_path; do
    if jq -e '
      if (has("status") and ((.status | ascii_downcase) == "running")) then
        true
      elif (.testcases?.status?.running // 0) > 0 then
        true
      else
        false
      end
    ' "$json_path" >/dev/null 2>&1; then
      return 0
    fi
  done < <(find "$fetch_output_dir" -type f \( -name build.json -o -name session.json \) -print0 2>/dev/null)

  return 1
}

run_once() {
  local attempt="$1"
  local attempt_log="${log_dir}/attempt-${attempt}.log"
  local device
  local build_id=""
  local -a cmd device_specs

  retryable=0
  rm -rf "$output_dir" "$fetch_output_dir"
  mkdir -p "$(dirname "$output_dir")" "$(dirname "$fetch_output_dir")"

  cmd=(
    cargo-mobench ci run
    --target "$platform"
    --functions "$functions_arg"
    --iterations "$iterations"
    --warmup "$warmup"
  )

  if [[ "$platform" == "ios" && -n "$ios_completion_timeout_secs" ]]; then
    cmd+=(--ios-completion-timeout-secs "$ios_completion_timeout_secs")
  fi

  IFS=',' read -r -a device_specs <<<"${device_specs_csv}"
  for device in "${device_specs[@]}"; do
    device="$(echo "$device" | xargs)"
    if [[ -n "$device" ]]; then
      cmd+=(--devices "$device")
    fi
  done

  cmd+=(--crate-path "$crate_path")
  if [[ -n "$release_flag" ]]; then
    cmd+=("$release_flag")
  fi
  cmd+=(
    --fetch
    --fetch-timeout-secs "$fetch_timeout_secs"
    --fetch-output-dir "$fetch_output_dir"
    --output-dir "$output_dir"
  )

  echo "mobench ${platform}: attempt ${attempt}/${max_attempts}"
  printf 'Command: '
  printf '%q ' "${cmd[@]}"
  echo

  set +e
  "${cmd[@]}" 2>&1 | tee "$attempt_log"
  last_status=${PIPESTATUS[0]}
  set -e

  if [ "$last_status" -eq 0 ]; then
    return 0
  fi

  if is_transient_fetch_failure "$attempt_log"; then
    retryable=1
    build_id="$(grep -Eo 'Build ID: [a-f0-9]+' "$attempt_log" | awk '{print $3}' | tail -1 || true)"
    if [[ -n "$build_id" ]]; then
      echo "::warning::Transient BrowserStack fetch failure for ${platform} build ${build_id}; retrying"
    else
      echo "::warning::Transient BrowserStack fetch failure for ${platform}; retrying"
    fi
  fi

  return "$last_status"
}

attempt=1
while true; do
  if run_once "$attempt"; then
    exit 0
  fi

  if [ "$retryable" -eq 1 ] && [ "$attempt" -lt "$max_attempts" ]; then
    attempt=$((attempt + 1))
    echo "Sleeping ${retry_sleep_secs}s before retrying ${platform} mobench fetch"
    sleep "$retry_sleep_secs"
    continue
  fi

  exit "$last_status"
done
