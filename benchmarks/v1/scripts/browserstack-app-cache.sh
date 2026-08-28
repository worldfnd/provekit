#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <id|lookup|upload> <ios|android> <fixture-manifest.json> <app.ipa|app.apk>" >&2
  exit 2
fi

action="$1"
platform="$2"
manifest="$3"
app="$4"

case "${action}" in
  id | lookup | upload) ;;
  *)
    echo "error: action must be id, lookup, or upload" >&2
    exit 1
    ;;
esac

case "${platform}" in
  ios)
    endpoint="xcuitest/v2"
    ;;
  android)
    endpoint="espresso/v2"
    ;;
  *)
    echo "error: platform must be ios or android" >&2
    exit 1
    ;;
esac

for command in curl jq stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ ! -f "${manifest}" || ! -f "${app}" ]]; then
  echo "error: fixture manifest and app package must be regular files" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_stdin() {
    sha256sum | awk '{print $1}'
  }
  app_sha256="$(sha256sum "${app}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  hash_stdin() {
    shasum -a 256 | awk '{print $1}'
  }
  app_sha256="$(shasum -a 256 "${app}" | awk '{print $1}')"
else
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi
if stat -f '%z' "${app}" >/dev/null 2>&1; then
  app_bytes="$(stat -f '%z' "${app}")"
else
  app_bytes="$(stat -c '%s' "${app}")"
fi

campaign_hash="$(jq -er '.campaign_hash | select(test("^[0-9a-f]{64}$"))' "${manifest}")"
cache_slug="$(jq -er '.cache_slug | select(test("^[a-z0-9-]+$"))' "${manifest}")"
actual_campaign_hash="$(
  jq 'del(.campaign_hash, .browserstack_fixture_id_prefixes)' "${manifest}" |
    jq -S -c . |
    hash_stdin
)"
if [[ "${actual_campaign_hash}" != "${campaign_hash}" ]]; then
  echo "error: fixture manifest campaign hash mismatch" >&2
  exit 1
fi
custom_id="pkv1-g16-${platform}-${cache_slug}-${campaign_hash:0:12}-${app_sha256:0:12}"

if [[ "${action}" == "id" ]]; then
  jq -n \
    --arg platform "${platform}" \
    --arg custom_id "${custom_id}" \
    --arg campaign_hash "${campaign_hash}" \
    --arg app_sha256 "${app_sha256}" \
    --argjson app_bytes "${app_bytes}" \
    '{
      platform: $platform,
      custom_id: $custom_id,
      campaign_hash: $campaign_hash,
      app_sha256: $app_sha256,
      app_bytes: $app_bytes
    }'
  exit 0
fi

if [[ -z "${BROWSERSTACK_USERNAME:-}" || -z "${BROWSERSTACK_ACCESS_KEY:-}" ]]; then
  echo "error: BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY are required" >&2
  exit 1
fi

api="https://api-cloud.browserstack.com/app-automate/${endpoint}"
lookup="$(
  curl -fsS \
    -u "${BROWSERSTACK_USERNAME}:${BROWSERSTACK_ACCESS_KEY}" \
    "${api}/apps?custom_id=${custom_id}"
)"
cached="$(
  jq -c '
    (
      if type == "array" then .
      elif (.apps | type) == "array" then .apps
      else []
      end
    )
    | sort_by(.uploaded_at // .uploaded_at_ms // .id // "")
    | last // empty
  ' <<<"${lookup}"
)"

if [[ -n "${cached}" ]]; then
  jq -n \
    --arg status "hit" \
    --arg custom_id "${custom_id}" \
    --arg campaign_hash "${campaign_hash}" \
    --arg app_sha256 "${app_sha256}" \
    --argjson app_bytes "${app_bytes}" \
    --argjson browserstack "${cached}" \
    '{
      status: $status,
      custom_id: $custom_id,
      campaign_hash: $campaign_hash,
      app_sha256: $app_sha256,
      app_bytes: $app_bytes,
      browserstack: $browserstack
    }'
  exit 0
fi

if [[ "${action}" == "lookup" ]]; then
  jq -n \
    --arg status "miss" \
    --arg custom_id "${custom_id}" \
    --arg campaign_hash "${campaign_hash}" \
    --arg app_sha256 "${app_sha256}" \
    --argjson app_bytes "${app_bytes}" \
    '{
      status: $status,
      custom_id: $custom_id,
      campaign_hash: $campaign_hash,
      app_sha256: $app_sha256,
      app_bytes: $app_bytes
    }'
  exit 3
fi

uploaded="$(
  curl -fsS \
    -u "${BROWSERSTACK_USERNAME}:${BROWSERSTACK_ACCESS_KEY}" \
    -X POST "${api}/app" \
    -F "file=@${app}" \
    -F "custom_id=${custom_id}"
)"
jq -n \
  --arg status "uploaded" \
  --arg custom_id "${custom_id}" \
  --arg campaign_hash "${campaign_hash}" \
  --arg app_sha256 "${app_sha256}" \
  --argjson app_bytes "${app_bytes}" \
  --argjson browserstack "${uploaded}" \
  '{
    status: $status,
    custom_id: $custom_id,
    campaign_hash: $campaign_hash,
    app_sha256: $app_sha256,
    app_bytes: $app_bytes,
    browserstack: $browserstack
  }'
