#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
usage: run-android-browserstack-shards.sh [options]

Run one BrowserStack build per Android function/device. Completed shards are
skipped; logs, build IDs, diagnostics, and results survive later failures.

Options:
  --manifest PATH       Mobench prebuilt manifest.json
  --output-dir PATH     Persistent shard output directory
  --device LABEL        BrowserStack device label (repeatable)
  --only-function NAME  Fully-qualified function to run (repeatable)
  --mobench-bin PATH    cargo-mobench binary (default: cargo-mobench)
  --retry-failed        Retry previously failed paid shards
  --dry-run             Verify bundles without spending BrowserStack capacity
  -h, --help            Show this help
EOF
}

manifest=""
output_dir=""
mobench_bin="${MOBENCH_BIN:-cargo-mobench}"
dry_run=0
retry_failed=0
devices=()
only_functions=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --manifest) manifest="${2:?missing --manifest value}"; shift 2 ;;
    --output-dir) output_dir="${2:?missing --output-dir value}"; shift 2 ;;
    --device) devices+=("${2:?missing --device value}"); shift 2 ;;
    --only-function) only_functions+=("${2:?missing --only-function value}"); shift 2 ;;
    --mobench-bin) mobench_bin="${2:?missing --mobench-bin value}"; shift 2 ;;
    --retry-failed) retry_failed=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for command in jq shasum stat; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
command -v "${mobench_bin}" >/dev/null 2>&1 || {
  echo "error: Mobench binary not found: ${mobench_bin}" >&2
  exit 1
}
[[ -n "${manifest}" && -f "${manifest}" ]] || {
  echo "error: --manifest must name a regular manifest.json" >&2
  exit 1
}
[[ "$(basename "${manifest}")" == "manifest.json" ]] || {
  echo "error: Mobench requires the manifest to be named manifest.json" >&2
  exit 1
}

manifest="$(cd "$(dirname "${manifest}")" && pwd -P)/manifest.json"
manifest_root="$(dirname "${manifest}")"
output_dir="${output_dir:-${manifest_root}/android-sharded-results}"
mkdir -p "${output_dir}/bundles" "${output_dir}/shards"
output_dir="$(cd "${output_dir}" && pwd -P)"

schema="$(jq -er '.schema' "${manifest}")"
platform="$(jq -er '.platform' "${manifest}")"
source_sha="$(jq -er '.source_sha | select(test("^[0-9a-f]{40}$"))' "${manifest}")"
mobench_version="$(jq -er '.mobench_version' "${manifest}")"
entry_count="$(jq -er '.entries | length | select(. > 0)' "${manifest}")"
iterations="$(jq -er '.entries[0].iterations' "${manifest}")"
warmup="$(jq -er '.entries[0].warmup' "${manifest}")"

[[ "${schema}" == "mobench.prebuilt.v1" && "${platform}" == "android" ]] || {
  echo "error: expected an Android mobench.prebuilt.v1 manifest" >&2
  exit 1
}
jq -e --argjson iterations "${iterations}" --argjson warmup "${warmup}" \
  'all(.entries[]; .iterations == $iterations and .warmup == $warmup)' \
  "${manifest}" >/dev/null || {
  echo "error: every entry must use one iterations/warmup contract" >&2
  exit 1
}

if [[ "${#devices[@]}" -eq 0 ]]; then
  devices=(
    "Samsung Galaxy S24-14.0"
    "Google Pixel 7-13.0"
    "Samsung Galaxy M32-11.0"
  )
fi
if [[ "${dry_run}" -eq 0 ]] &&
  { [[ -z "${BROWSERSTACK_USERNAME:-}" ]] || [[ -z "${BROWSERSTACK_ACCESS_KEY:-}" ]]; }; then
  echo "error: set BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY locally" >&2
  exit 1
fi

slugify() {
  printf '%s' "$1" |
    tr '[:upper:]' '[:lower:]' |
    sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' |
    cut -c1-96
}

is_selected_function() {
  local candidate="$1"
  local selected
  [[ "${#only_functions[@]}" -eq 0 ]] && return 0
  for selected in "${only_functions[@]}"; do
    [[ "${candidate}" == "${selected}" ]] && return 0
  done
  return 1
}

copy_clone() {
  cp -c "$1" "$2" 2>/dev/null || cp "$1" "$2"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

file_size() {
  stat -f '%z' "$1" 2>/dev/null || stat -c '%s' "$1"
}

write_index() {
  local index_tmp="${output_dir}/index.json.tmp"
  local status_files=()
  local status_file
  while IFS= read -r status_file; do
    status_files+=("${status_file}")
  done < <(find "${output_dir}/shards" -type f -name status.json -print | sort)

  if [[ "${#status_files[@]}" -eq 0 ]]; then
    jq -n --arg source_sha "${source_sha}" --arg version "${mobench_version}" \
      --arg manifest "${manifest}" '{
        schema: "provekit.android-browserstack-shards.v1",
        source_sha: $source_sha,
        mobench_version: $version,
        source_manifest: $manifest,
        shards: []
      }' >"${index_tmp}"
  else
    jq -s --arg source_sha "${source_sha}" --arg version "${mobench_version}" \
      --arg manifest "${manifest}" '{
        schema: "provekit.android-browserstack-shards.v1",
        source_sha: $source_sha,
        mobench_version: $version,
        source_manifest: $manifest,
        shards: sort_by(.function, .device)
      }' "${status_files[@]}" >"${index_tmp}"
  fi
  mv "${index_tmp}" "${output_dir}/index.json"
}

capture_stream() {
  local log_path="$1"
  local build_id_path="$2"
  local line
  while IFS= read -r line; do
    printf '%s\n' "${line}" | tee -a "${log_path}"
    case "${line}" in
      *"Build ID: "*)
        printf '%s\n' "${line##*Build ID: }" >"${build_id_path}.tmp"
        mv "${build_id_path}.tmp" "${build_id_path}"
        ;;
    esac
  done
}

manifest_sha256="$(sha256_file "${manifest}")"
selected_count=0

for ((entry_index = 0; entry_index < entry_count; entry_index++)); do
  function="$(jq -er --argjson index "${entry_index}" '.entries[$index].function' "${manifest}")"
  is_selected_function "${function}" || continue
  selected_count=$((selected_count + 1))

  function_slug="$(slugify "${function}")"
  bundle_dir="${output_dir}/bundles/$(printf '%04d' "${entry_index}")-${function_slug}"
  bundle_manifest="${bundle_dir}/manifest.json"
  source_entry_dir="${manifest_root}/entries/$(printf '%04d' "${entry_index}")"
  bundle_entry_dir="${bundle_dir}/entries/0000"

  if [[ ! -f "${bundle_manifest}" ]]; then
    mkdir -p "${bundle_entry_dir}"
    copy_clone "${source_entry_dir}/app.apk" "${bundle_entry_dir}/app.apk"
    copy_clone "${source_entry_dir}/test.apk" "${bundle_entry_dir}/test.apk"
    jq --argjson index "${entry_index}" '
      .entries = [.entries[$index]]
      | .entries[0].artifacts |= map(
          .path |= sub("^entries/[0-9]{4}/"; "entries/0000/")
        )
    ' "${manifest}" >"${bundle_manifest}.tmp"
    mv "${bundle_manifest}.tmp" "${bundle_manifest}"
  fi

  for artifact in app test; do
    if [[ "${artifact}" == "app" ]]; then
      artifact_kind="android-app"
    else
      artifact_kind="android-test-suite"
    fi
    expected_size="$(jq -er --arg kind "${artifact_kind}" \
      '.entries[0].artifacts[] | select(.kind == $kind) | .size' "${bundle_manifest}")"
    expected_sha="$(jq -er --arg kind "${artifact_kind}" \
      '.entries[0].artifacts[] | select(.kind == $kind) | .sha256' "${bundle_manifest}")"
    actual_path="${bundle_entry_dir}/${artifact}.apk"
    [[ "$(file_size "${actual_path}")" == "${expected_size}" &&
      "$(sha256_file "${actual_path}")" == "${expected_sha}" ]] || {
      echo "error: immutable bundle verification failed for ${function}" >&2
      exit 1
    }
  done

  if [[ "${dry_run}" -eq 1 ]]; then
    echo "[dry-run] verify function=${function}"
    "${mobench_bin}" --dry-run ci run-prebuilt \
      --manifest "${bundle_manifest}" \
      --expected-source-sha "${source_sha}" \
      --expected-platform android \
      --expected-functions "${function}" \
      --expected-iterations "${iterations}" \
      --expected-warmup "${warmup}" \
      --devices "${devices[0]}" \
      --max-completion-timeout-secs 7200
    continue
  fi

  for device in "${devices[@]}"; do
    device_slug="$(slugify "${device}")"
    shard_dir="${output_dir}/shards/$(printf '%04d' "${entry_index}")-${function_slug}/${device_slug}"
    result_dir="${shard_dir}/result"
    fetch_dir="${shard_dir}/browserstack"
    status_path="${shard_dir}/status.json"
    log_path="${shard_dir}/attempt.log"
    build_id_path="${shard_dir}/build-id.txt"
    mkdir -p "${shard_dir}"

    if [[ -f "${result_dir}/summary.json" ]] &&
      jq -e --arg function "${function}" --arg device "${device}" '
        (.functions[$function].summary.function == $function)
        and (.functions[$function].summary.devices == [$device])
      ' "${result_dir}/summary.json" >/dev/null; then
      echo "[skip completed] ${function} on ${device}"
      continue
    fi
    if [[ -f "${status_path}" && "${retry_failed}" -eq 0 ]] &&
      jq -e '.outcome == "failed"' "${status_path}" >/dev/null; then
      echo "[skip failed; pass --retry-failed] ${function} on ${device}"
      continue
    fi

    started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    jq -n --arg function "${function}" --arg device "${device}" \
      --arg source_sha "${source_sha}" --arg manifest_sha256 "${manifest_sha256}" \
      --arg started_at "${started_at}" '{
        schema: "provekit.android-browserstack-shard-request.v1",
        function: $function,
        device: $device,
        source_sha: $source_sha,
        source_manifest_sha256: $manifest_sha256,
        credential_source: "env",
        started_at: $started_at
      }' >"${shard_dir}/request.json.tmp"
    mv "${shard_dir}/request.json.tmp" "${shard_dir}/request.json"
    : >"${log_path}"

    echo "[run] ${function} on ${device}"
    command_args=(
      "${mobench_bin}" ci run-prebuilt
      --manifest "${bundle_manifest}"
      --expected-source-sha "${source_sha}"
      --expected-platform android
      --expected-functions "${function}"
      --expected-iterations "${iterations}"
      --expected-warmup "${warmup}"
      --devices "${device}"
      --output-dir "${result_dir}"
      --fetch
      --fetch-output-dir "${fetch_dir}"
      --fetch-poll-interval-secs 10
      --fetch-timeout-secs 7200
      --max-completion-timeout-secs 7200
    )

    set +e
    "${command_args[@]}" 2>&1 | capture_stream "${log_path}" "${build_id_path}"
    command_status="${PIPESTATUS[0]}"
    set -e

    finished_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    build_id=""
    [[ ! -f "${build_id_path}" ]] || build_id="$(tr -d '\r\n' <"${build_id_path}")"
    if [[ "${command_status}" -eq 0 && -f "${result_dir}/summary.json" ]]; then
      outcome="success"
    else
      outcome="failed"
    fi
    jq -n --arg function "${function}" --arg device "${device}" \
      --arg source_sha "${source_sha}" --arg build_id "${build_id}" \
      --arg outcome "${outcome}" --arg started_at "${started_at}" \
      --arg finished_at "${finished_at}" --arg log "${log_path}" \
      --arg summary "${result_dir}/summary.json" --argjson exit_code "${command_status}" '{
        schema: "provekit.android-browserstack-shard-status.v1",
        function: $function,
        device: $device,
        source_sha: $source_sha,
        build_id: ($build_id | if length > 0 then . else null end),
        outcome: $outcome,
        exit_code: $exit_code,
        started_at: $started_at,
        finished_at: $finished_at,
        log: $log,
        summary: (if $outcome == "success" then $summary else null end)
      }' >"${status_path}.tmp"
    mv "${status_path}.tmp" "${status_path}"
    write_index

    [[ "${command_status}" -eq 0 ]] ||
      echo "[failed] ${function} on ${device}; inspect ${log_path}" >&2
  done
done

[[ "${selected_count}" -gt 0 ]] || {
  echo "error: no selected function exists in the manifest" >&2
  exit 1
}
write_index
if [[ "${dry_run}" -eq 1 ]]; then
  echo "Dry run complete: ${selected_count} function bundle(s) verified."
else
  jq -r '
    ([.shards[] | select(.outcome == "success")] | length) as $success
    | ([.shards[] | select(.outcome == "failed")] | length) as $failed
    | "Android shard index updated: \($success) success, \($failed) failed"
  ' "${output_dir}/index.json"
fi
