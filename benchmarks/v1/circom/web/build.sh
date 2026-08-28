#!/usr/bin/env bash

set -euo pipefail

web_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${web_root}/../.." && pwd)"
dist="${CIRCOM_BROWSER_DIST:-${web_root}/dist}"
fixture_root="${CIRCOM_BROWSER_FIXTURE_ROOT:-${benchmark_root}/../../target/v1-benchmarks/circom-browser}"
profile="${CIRCOM_BROWSER_PROFILE:-historical}"

cd "${web_root}"
bun install --frozen-lockfile

manifest="${fixture_root}/manifest.json"
if [[ ! -f "${manifest}" ]]; then
  echo "error: missing frozen Circom browser fixture manifest ${manifest}" >&2
  echo "prepare circuit.wasm, final.zkey, verification key, and input files first" >&2
  exit 1
fi

rm -rf "${dist}"
mkdir -p "${dist}/assets"
bun build runner.ts --outdir "${dist}" --target browser --format esm --minify
cp "${web_root}/index.html" "${dist}/index.html"
cp -R "${fixture_root}/." "${dist}/assets/"

case "${profile}" in
  historical)
    jq -e '
      .schema_version == 1
      and ([.fixtures.passport[], .fixtures.webauthn[], .fixtures.oprf[]] | length >= 3)
      and all(.fixtures[][]; .semantic_equivalence == "closest-analogue-not-equivalent")
    ' "${dist}/assets/manifest.json" >/dev/null
    ;;
  p1)
    jq -e '
      .schema_version == 1
      and (.fixtures.passport | length == 1)
      and (.fixtures.passport[0].profile == "P1")
      and (.fixtures.passport[0].semantic_equivalence == "p1-matched-monolithic")
      and (.fixtures.passport[0].ceremony.production_safe == false)
    ' "${dist}/assets/manifest.json" >/dev/null
    ;;
  *)
    echo "error: unknown CIRCOM_BROWSER_PROFILE ${profile}" >&2
    exit 1
    ;;
esac

echo "Built SnarkJS browser benchmark at ${dist}"
