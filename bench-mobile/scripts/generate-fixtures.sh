#!/usr/bin/env bash
set -euo pipefail

if [[ "${MOBENCH_CI_PREPARE:-}" != "1" ]]; then
  echo "MOBENCH_CI_PREPARE=1 is required to generate mobile benchmark fixtures" >&2
  exit 1
fi

noir_version="v1.0.0-beta.25"
if ! command -v noirup >/dev/null 2>&1; then
  curl --fail --location --proto '=https' --tlsv1.2 \
    https://raw.githubusercontent.com/noir-lang/noirup/dedc07043b6ae9a680a19c7394847a58e404cbba/install | bash
  export PATH="$HOME/.nargo/bin:$PATH"
fi
noirup --version "$noir_version"
command -v nargo >/dev/null 2>&1 || {
  echo "nargo was not installed by noirup $noir_version" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

compile_fixture() {
  local circuit_dir="$1"
  local aggregate_target_dir="${2:-}"
  echo "Generating Noir artifact in ${circuit_dir}"
  (
    cd "${repo_root}/${circuit_dir}"
    nargo compile --skip-brillig-constraints-check --force
  )

  if [[ -n "${aggregate_target_dir}" ]]; then
    local circuit_target_dir="${repo_root}/${circuit_dir}/target"
    local target_dir="${repo_root}/${aggregate_target_dir}"
    mkdir -p "${target_dir}"
    if compgen -G "${circuit_target_dir}/*.json" >/dev/null; then
      cp "${circuit_target_dir}"/*.json "${target_dir}/"
    fi
  fi
}

compile_oprf_benchmark_fixture() (
  local source_dir="${repo_root}/noir-examples/oprf"
  local fixture_dir
  fixture_dir=$(mktemp -d "${repo_root}/noir-examples/.oprf-bench.XXXXXX")
  trap 'rm -rf "${fixture_dir}"' EXIT

  echo "Generating benchmark-only Noir artifact from noir-examples/oprf"
  cp "${source_dir}/Nargo.toml" "${source_dir}/Prover.toml" "${fixture_dir}/"
  cp -R "${source_dir}/src" "${fixture_dir}/src"
  cp "${repo_root}/bench-mobile/scripts/oprf-benchmark-main.nr" "${fixture_dir}/src/main.nr"

  (
    cd "${fixture_dir}"
    nargo compile --skip-brillig-constraints-check --force
  )

  mkdir -p "${source_dir}/target"
  cp "${fixture_dir}/target/oprf.json" "${source_dir}/target/oprf.json"
)

compile_fixture "noir-examples/noir-passport-monolithic/complete_age_check"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_dsc_720" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_id_data_720" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_integrity_commit" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_attest" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_oprf_benchmark_fixture
compile_fixture "noir-examples/p256_bigcurve"
