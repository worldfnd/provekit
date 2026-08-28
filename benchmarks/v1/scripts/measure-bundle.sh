#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <bundle-files.tsv> <output.json>" >&2
  exit 2
fi

manifest="$1"
output="$2"

for command in jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ ! -f "${manifest}" ]]; then
  echo "error: manifest not found: ${manifest}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() {
    sha256sum "$1" | awk '{print $1}'
  }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
else
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi

size_file() {
  if stat -f '%z' "$1" >/dev/null 2>&1; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

rows_file="$(mktemp "${TMPDIR:-/tmp}/provekit-v1-bundle.XXXXXX")"
cleanup() {
  rm -f "${rows_file}"
}
trap cleanup EXIT

line_number=0
while IFS=$'\t' read -r scope kind path mime_type extra; do
  line_number=$((line_number + 1))

  if [[ -z "${scope}" || "${scope}" == \#* ]]; then
    continue
  fi

  if [[ -n "${extra:-}" || -z "${kind}" || -z "${path}" ]]; then
    echo "error: ${manifest}:${line_number}: expected 3 or 4 tab-separated fields" >&2
    exit 1
  fi

  if [[ ! -f "${path}" ]]; then
    echo "error: ${manifest}:${line_number}: artifact is not a regular file: ${path}" >&2
    exit 1
  fi

  bytes="$(size_file "${path}")"
  sha256="$(hash_file "${path}")"

  jq -cn \
    --arg scope "${scope}" \
    --arg kind "${kind}" \
    --arg path "${path}" \
    --arg mime_type "${mime_type:-}" \
    --arg sha256 "${sha256}" \
    --argjson bytes "${bytes}" \
    '{
      scope: $scope,
      kind: $kind,
      path: $path,
      bytes: $bytes,
      sha256: $sha256
    } + if $mime_type == "" then {} else {mime_type: $mime_type} end' \
    >>"${rows_file}"
done <"${manifest}"

mkdir -p "$(dirname "${output}")"

jq -s \
  '{
    schema_version: 1,
    artifacts: .,
    totals: (
      group_by(.scope)
      | map({
          key: .[0].scope,
          value: (map(.bytes) | add)
        })
      | from_entries
    )
  }' \
  "${rows_file}" >"${output}"

echo "Wrote ${output}"
