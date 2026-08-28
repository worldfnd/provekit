#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
world_id="${repo_root}/target/v1-benchmarks/sources/world-id-protocol"

"${script_dir}/bootstrap-sources.sh"
"${script_dir}/verify-circom-artifacts.sh"

(
  cd "${world_id}"
  cargo check -p zk-mobile-bench
  cargo test -p zk-mobile-bench \
    tests::test_query_proof_benchmark \
    -- \
    --ignored \
    --exact \
    --nocapture
)

echo "Arkworks World ID OPRF query proof smoke passed"
