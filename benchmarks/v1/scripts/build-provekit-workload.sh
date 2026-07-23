#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <webauthn_assertion|passport_complete_age_check|oprf_taceo>" >&2
  exit 2
fi

workload="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"

case "${workload}" in
  webauthn_assertion)
    circuit_dir="${benchmark_root}/noir/webauthn_assertion"
    input="${circuit_dir}/Prover.toml"
    ;;
  passport_complete_age_check)
    circuit_dir="${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check"
    input="${circuit_dir}/Prover.toml"
    ;;
  oprf_taceo)
    circuit_dir="${repo_root}/target/v1-benchmarks/sources/oprf-nr/oprf_example"
    input="${circuit_dir}/Prover.toml"
    ;;
  *)
    echo "error: unsupported ProveKit workload ${workload}" >&2
    exit 2
    ;;
esac

artifact_dir="${repo_root}/target/v1-benchmarks/artifacts/${workload}"
compile_dir="${repo_root}/target/v1-benchmarks/noir/${workload}"
manifest_output="${artifact_dir}/manifest.json"

for command in cargo jq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: ${command} is required" >&2
    exit 1
  fi
done

if [[ "${V1_BENCHMARK_SKIP_NOIR_COMPILE:-0}" != "1" ]]; then
  "${script_dir}/compile-noir-workloads.sh"
fi
mkdir -p "${artifact_dir}" "${compile_dir}"
cargo build --release -p provekit-cli

cli="${repo_root}/target/release/provekit-cli"
pkp="${artifact_dir}/${workload}.pkp"
pkv="${artifact_dir}/${workload}.pkv"
proof="${artifact_dir}/${workload}.np"

if [[ "${V1_BENCHMARK_REUSE_ARTIFACTS:-0}" == "1" ]]; then
  for artifact in "${pkp}" "${pkv}" "${proof}"; do
    if [[ ! -f "${artifact}" ]]; then
      echo "error: cannot reuse missing artifact ${artifact}" >&2
      exit 1
    fi
  done
else
"${cli}" prepare \
  --target-dir "${compile_dir}" \
  --skip-brillig-constraints-check \
  --force \
  --pkp "${pkp}" \
  --pkv "${pkv}" \
  "${circuit_dir}"
"${cli}" prove --prover "${pkp}" --input "${input}" --out "${proof}"
fi
"${cli}" verify --verifier "${pkv}" --proof "${proof}"

manifest="$(mktemp "${TMPDIR:-/tmp}/provekit-v1-${workload}.XXXXXX.tsv")"
cleanup() {
  rm -f "${manifest}"
}
trap cleanup EXIT
{
  printf '# scope\tkind\tpath\n'
  printf 'prover-download\tprovekit-pkp\t%s\n' "${pkp}"
  printf 'verifier-download\tprovekit-pkv\t%s\n' "${pkv}"
  printf 'result\tprovekit-proof\t%s\n' "${proof}"
} >"${manifest}"

(
  cd "${repo_root}"
  "${script_dir}/measure-bundle.sh" "${manifest}" "${manifest_output}"
)

jq -e '
  .totals["prover-download"] > 0
    and .totals["verifier-download"] > 0
    and .totals.result > 0
' "${manifest_output}" >/dev/null

echo "Prepared and verified ProveKit ${workload} artifacts under ${artifact_dir}"
