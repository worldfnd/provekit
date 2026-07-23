#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
nargo_bin="$("${script_dir}/bootstrap-nargo.sh")"

"${script_dir}/bootstrap-sources.sh"

(
  cd "${benchmark_root}/noir/webauthn_assertion"
  bun install --frozen-lockfile
  bun run fixture
  "${nargo_bin}" compile --skip-brillig-constraints-check --force
)

(
  cd "${repo_root}/noir-examples/noir-passport-monolithic/complete_age_check"
  "${nargo_bin}" compile --skip-brillig-constraints-check --force
)

(
  cd "${repo_root}/target/v1-benchmarks/sources/oprf-nr/oprf_example"
  "${nargo_bin}" compile --skip-brillig-constraints-check --force
)

echo "Compiled WebAuthn, passport, and Taceo OPRF with pinned Noir"
