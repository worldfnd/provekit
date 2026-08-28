#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 3 ]]; then
  echo "usage: $0 OUTPUT_ROOT MANIFEST MANIFEST [MANIFEST ...]" >&2
  exit 2
fi

output_root="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
shift
manifests=("$@")

for command in cp jq shasum stat; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

case "${output_root}" in
  */target/v1-benchmarks/*-ios-prebuilt)
    ;;
  *)
    echo "error: output must be a target/v1-benchmarks/*-ios-prebuilt directory" >&2
    exit 2
    ;;
esac

parent="$(dirname "${output_root}")"
work_root="$(mktemp -d "${parent}/merged-ios-prebuilt.XXXXXX")"
cleanup() {
  case "${work_root}" in
    "${parent}"/merged-ios-prebuilt.*)
      rm -rf "${work_root}"
      ;;
    *)
      echo "error: refusing to clean unexpected merge path: ${work_root}" >&2
      ;;
  esac
}
trap cleanup EXIT

entries_file="${work_root}/entries.jsonl"
provenance_file="${work_root}/provenance.jsonl"
: >"${entries_file}"
: >"${provenance_file}"
entry_index=0

copy_artifact() {
  local source="$1"
  local destination="$2"
  cp -c "${source}" "${destination}" 2>/dev/null ||
    cp "${source}" "${destination}"
}

for manifest in "${manifests[@]}"; do
  manifest="$(cd "$(dirname "${manifest}")" && pwd)/$(basename "${manifest}")"
  jq -e '
    .schema == "mobench.prebuilt.v1" and
    .platform == "ios" and
    (.source_sha | test("^[0-9a-f]{40}$")) and
    (.entries | length > 0)
  ' "${manifest}" >/dev/null

  manifest_root="$(dirname "${manifest}")"
  jq -cn \
    --arg manifest "${manifest}" \
    --arg source_sha "$(jq -er '.source_sha' "${manifest}")" \
    --arg sha256 "$(shasum -a 256 "${manifest}" | awk '{print $1}')" \
    '{
      manifest: $manifest,
      source_sha: $source_sha,
      manifest_sha256: $sha256
    }' >>"${provenance_file}"

  entry_count="$(jq -r '.entries | length' "${manifest}")"
  for ((source_index = 0; source_index < entry_count; source_index++)); do
    entry="$(printf '%04d' "${entry_index}")"
    destination="${work_root}/entries/${entry}"
    mkdir -p "${destination}"

    function="$(jq -er ".entries[${source_index}].function" "${manifest}")"
    iterations="$(jq -er ".entries[${source_index}].iterations" "${manifest}")"
    warmup="$(jq -er ".entries[${source_index}].warmup" "${manifest}")"
    timeout="$(
      jq -er \
        ".entries[${source_index}].completion_timeout_secs // 7200" \
        "${manifest}"
    )"

    artifacts_file="${work_root}/artifacts-${entry}.jsonl"
    : >"${artifacts_file}"
    artifact_count="$(
      jq -r ".entries[${source_index}].artifacts | length" "${manifest}"
    )"
    for ((artifact_index = 0; artifact_index < artifact_count; artifact_index++)); do
      kind="$(
        jq -er \
          ".entries[${source_index}].artifacts[${artifact_index}].kind" \
          "${manifest}"
      )"
      relative_path="$(
        jq -er \
          ".entries[${source_index}].artifacts[${artifact_index}].path" \
          "${manifest}"
      )"
      expected_size="$(
        jq -er \
          ".entries[${source_index}].artifacts[${artifact_index}].size" \
          "${manifest}"
      )"
      expected_hash="$(
        jq -er \
          ".entries[${source_index}].artifacts[${artifact_index}].sha256" \
          "${manifest}"
      )"
      source="${manifest_root}/${relative_path}"
      [[ -f "${source}" ]] || {
        echo "error: missing prebuilt artifact ${source}" >&2
        exit 1
      }
      [[ "$(stat -f '%z' "${source}")" == "${expected_size}" ]] || {
        echo "error: size mismatch for ${source}" >&2
        exit 1
      }
      [[ "$(shasum -a 256 "${source}" | awk '{print $1}')" == "${expected_hash}" ]] || {
        echo "error: hash mismatch for ${source}" >&2
        exit 1
      }

      filename="$(basename "${relative_path}")"
      copied="${destination}/${filename}"
      copy_artifact "${source}" "${copied}"
      copied_path="entries/${entry}/${filename}"
      jq -cn \
        --arg kind "${kind}" \
        --arg path "${copied_path}" \
        --arg sha256 "${expected_hash}" \
        --argjson size "${expected_size}" \
        '{kind: $kind, path: $path, size: $size, sha256: $sha256}' \
        >>"${artifacts_file}"
    done

    jq -s \
      --arg function "${function}" \
      --argjson iterations "${iterations}" \
      --argjson warmup "${warmup}" \
      --argjson timeout "${timeout}" \
      '{
        function: $function,
        iterations: $iterations,
        warmup: $warmup,
        completion_timeout_secs: $timeout,
        artifacts: .
      }' "${artifacts_file}" >>"${entries_file}"
    entry_index=$((entry_index + 1))
  done
done

source_sha="$(
  jq -sc '.' "${provenance_file}" |
    shasum |
    awk '{print $1}'
)"
jq -s \
  --arg source_sha "${source_sha}" \
  '{
    schema: "mobench.prebuilt.v1",
    source_sha: $source_sha,
    platform: "ios",
    build_profile: "release",
    mobench_version: "0.2.0",
    abi: {
      benchmark: "mobench-bench-spec-v1",
      runner: "browserstack-xcuitest-v2"
    },
    entries: .
  }' "${entries_file}" >"${work_root}/manifest.json"
jq -s \
  --arg source_sha "${source_sha}" \
  '{
    schema: "provekit.merged-ios-prebuilt-provenance.v1",
    source_sha: $source_sha,
    inputs: .
  }' "${provenance_file}" >"${work_root}/provenance.json"

rm -f "${entries_file}" "${provenance_file}"
find "${work_root}" -maxdepth 1 -type f -name 'artifacts-*.jsonl' -delete

if [[ -e "${output_root}" ]]; then
  rm -rf "${output_root}"
fi
mv "${work_root}" "${output_root}"
mv "${output_root}/provenance.json" "${output_root}.provenance.json"
trap - EXIT
echo "${output_root}/manifest.json"
