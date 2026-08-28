#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_revision="${V1_PROVEKIT_FIXTURE_SOURCE_REVISION:-$(jq -er '.provekit_v1.beta11_fixture_harness_commit' "${benchmark_root}/toolchains.lock.json")}"
snapshot_root="${repo_root}/target/v1-benchmarks/provekit-beta11-source"
artifact_root="${repo_root}/target/v1-benchmarks/provekit-beta11-artifacts"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
nargo_home="${V1_BENCHMARK_NARGO_HOME:-${repo_root}/target/v1-benchmarks/nargo-home}"
tool_root="${V1_BENCHMARK_TOOL_ROOT:-${repo_root}/target/v1-benchmarks/tools}"

for command in git jq shasum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

cleanup() {
  if git -C "${repo_root}" worktree list --porcelain |
    grep -Fqx "worktree ${snapshot_root}"; then
    git -C "${repo_root}" worktree remove --force "${snapshot_root}"
  fi
}
trap cleanup EXIT

if [[ -e "${snapshot_root}" ]]; then
  if git -C "${repo_root}" worktree list --porcelain |
    grep -Fqx "worktree ${snapshot_root}"; then
    git -C "${repo_root}" worktree remove --force "${snapshot_root}"
  else
    echo "error: refusing to replace unregistered path ${snapshot_root}" >&2
    exit 1
  fi
fi

git -C "${repo_root}" worktree add --detach "${snapshot_root}" "${source_revision}"
mkdir -p "${snapshot_root}/target/v1-benchmarks"
ln -s "${source_root}" "${snapshot_root}/target/v1-benchmarks/sources"
(
  cd "${snapshot_root}"
  MOBENCH_CI_PREPARE=1 \
    PROVEKIT_REUSE_WEBAUTHN_FIXTURE=0 \
    V1_BENCHMARK_SOURCE_ROOT="${source_root}" \
    V1_BENCHMARK_NARGO_HOME="${nargo_home}" \
    V1_BENCHMARK_TOOL_ROOT="${tool_root}" \
    bench-mobile/scripts/generate-fixtures.sh
)

mkdir -p "${artifact_root}"
cp \
  "${snapshot_root}/noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json" \
  "${artifact_root}/complete_age_check.json"
cp \
  "${snapshot_root}/noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml" \
  "${artifact_root}/complete_age_check.Prover.toml"
cp \
  "${snapshot_root}/noir-examples/noir-passport/merkle_age_check/target/"{t_add_dsc_720.json,t_add_id_data_720.json,t_add_integrity_commit.json,t_attest.json} \
  "${artifact_root}/"
"${script_dir}/prepare-oprf-o2-beta11.sh" >/dev/null
cp \
  "${repo_root}/target/v1-benchmarks/oprf-o2-beta11/oprf/target/oprf.json" \
  "${artifact_root}/oprf.json"
cp \
  "${repo_root}/target/v1-benchmarks/oprf-o2-beta11/oprf/Prover.toml" \
  "${artifact_root}/oprf.Prover.toml"
"${script_dir}/prepare-passport-p1-beta11.sh" >/dev/null
cp \
  "${repo_root}/target/v1-benchmarks/passport-p1-beta11/target/passport_p1.json" \
  "${artifact_root}/passport_p1.json"
cp \
  "${repo_root}/target/v1-benchmarks/passport-p1-beta11/Prover.toml" \
  "${artifact_root}/passport_p1.Prover.toml"
cp "${snapshot_root}/noir-examples/p256_bigcurve/target/p256.json" "${artifact_root}/p256.json"
cp \
  "${snapshot_root}/benchmarks/v1/noir/webauthn_assertion/target/webauthn_assertion.json" \
  "${artifact_root}/webauthn_assertion.json"

for artifact in "${artifact_root}"/*.json; do
  [[ "$(basename "${artifact}")" != "manifest.json" ]] || continue
  version="$(jq -r '.noir_version' "${artifact}")"
  case "${version}" in
    1.0.0-beta.11+*) ;;
    *)
      echo "error: ${artifact} was compiled by incompatible Noir ${version}" >&2
      exit 1
      ;;
  esac
done

hashes="$(
  for artifact in "${artifact_root}"/*.json "${artifact_root}"/*.toml; do
    [[ "$(basename "${artifact}")" != "manifest.json" ]] || continue
    printf '%s %s\n' \
      "$(shasum -a 256 "${artifact}" | awk '{print $1}')" \
      "$(basename "${artifact}")"
  done
)"
jq -n \
  --arg source_revision "${source_revision}" \
  --arg noir_version "1.0.0-beta.11" \
  --arg hashes "${hashes}" \
  '{
    schema: "provekit.beta11-mobile-artifacts.v1",
    source_revision: $source_revision,
    noir_version: $noir_version,
    artifacts: (
      $hashes
      | split("\n")
      | map(select(length > 0) | split(" "))
      | map({key: .[1], value: .[0]})
      | from_entries
    )
  }' >"${artifact_root}/manifest.json"

echo "${artifact_root}/manifest.json"
