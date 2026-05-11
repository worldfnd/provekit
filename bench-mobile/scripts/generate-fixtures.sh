#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

compile_fixture() {
  local circuit_dir="$1"
  echo "Generating Noir artifact in ${circuit_dir}"
  (
    cd "${repo_root}/${circuit_dir}"
    nargo compile --skip-brillig-constraints-check --force
  )
}

compile_fixture "noir-examples/noir-passport-monolithic/complete_age_check"
compile_fixture "noir-examples/oprf"
compile_fixture "noir-examples/p256_bigcurve"
