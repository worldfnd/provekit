#!/usr/bin/env bash
set -euo pipefail

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

compile_fixture "noir-examples/noir-passport-monolithic/complete_age_check"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_dsc_720" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_id_data_720" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_add_integrity_commit" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/noir-passport/merkle_age_check/t_attest" \
  "noir-examples/noir-passport/merkle_age_check/target"
compile_fixture "noir-examples/oprf"
compile_fixture "noir-examples/p256_bigcurve"
