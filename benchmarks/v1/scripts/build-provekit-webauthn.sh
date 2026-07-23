#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
circuit_dir="${benchmark_root}/noir/webauthn_assertion"
artifact_dir="${repo_root}/target/v1-benchmarks/artifacts/webauthn_assertion"
compile_dir="${repo_root}/target/v1-benchmarks/noir/webauthn_assertion"
manifest="${benchmark_root}/manifests/webauthn-provekit-native.tsv"
manifest_output="${artifact_dir}/manifest.json"

for command in bun cargo jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

"${script_dir}/bootstrap-sources.sh"
nargo_bin="$("${script_dir}/bootstrap-nargo.sh")"

(
  cd "${circuit_dir}"
  bun install --frozen-lockfile
  bun run fixture
  "${nargo_bin}" compile --skip-brillig-constraints-check --force
)

mkdir -p "${artifact_dir}" "${compile_dir}"
cargo build --release -p provekit-cli

cli="${repo_root}/target/release/provekit-cli"
pkp="${artifact_dir}/webauthn_assertion.pkp"
pkv="${artifact_dir}/webauthn_assertion.pkv"
proof="${artifact_dir}/webauthn_assertion.np"

"${cli}" prepare \
  --target-dir "${compile_dir}" \
  --skip-brillig-constraints-check \
  --force \
  --pkp "${pkp}" \
  --pkv "${pkv}" \
  "${circuit_dir}"
"${cli}" prove --prover "${pkp}" --input "${circuit_dir}/Prover.toml" --out "${proof}"
"${cli}" verify --verifier "${pkv}" --proof "${proof}"

(
  cd "${repo_root}"
  "${script_dir}/measure-bundle.sh" "${manifest}" "${manifest_output}"
)

jq -e '
  .totals["prover-download"] > 0
    and .totals["verifier-download"] > 0
    and .totals.result > 0
' "${manifest_output}" >/dev/null

echo "Prepared and verified ProveKit WebAuthn artifacts under ${artifact_dir}"
