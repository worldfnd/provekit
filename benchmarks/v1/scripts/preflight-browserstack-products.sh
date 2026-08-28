#!/usr/bin/env bash

set -euo pipefail

for command in curl jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ -z "${BROWSERSTACK_USERNAME:-}" || -z "${BROWSERSTACK_ACCESS_KEY:-}" ]]; then
  echo "error: BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY are required" >&2
  exit 1
fi

check_plan() {
  local product="$1"
  local url="$2"
  local destination="$3"
  local status

  status="$(
    curl \
      --silent \
      --show-error \
      --user "${BROWSERSTACK_USERNAME}:${BROWSERSTACK_ACCESS_KEY}" \
      --output "${destination}" \
      --write-out '%{http_code}' \
      "${url}"
  )"
  if [[ "${status}" != "200" ]] || ! jq -e 'type == "object"' "${destination}" >/dev/null; then
    echo "error: BrowserStack ${product} plan check failed with HTTP ${status}" >&2
    return 1
  fi
  if jq -e 'has("message") and (.message | test("auth|access|subscription|upgrade"; "i"))' \
    "${destination}" >/dev/null; then
    echo "error: BrowserStack ${product} is not available to this account" >&2
    return 1
  fi
  echo "BrowserStack ${product}: authenticated plan endpoint available"
}

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/provekit-browserstack-plan.XXXXXX")"
cleanup() {
  rm -f "${work_dir}/automate.json" "${work_dir}/app-automate.json"
  rmdir "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT

check_plan \
  "Automate" \
  "https://api.browserstack.com/automate/plan.json" \
  "${work_dir}/automate.json"
check_plan \
  "App Automate" \
  "https://api-cloud.browserstack.com/app-automate/plan.json" \
  "${work_dir}/app-automate.json"

echo "Both BrowserStack products required by this benchmark are available."
