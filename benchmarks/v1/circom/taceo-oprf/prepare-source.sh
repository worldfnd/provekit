#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
source_root="${repo_root}/target/v1-benchmarks/taceo-v021/sources"
helpers="${source_root}/circom-helpers"
witness="${source_root}/circom-witness-rs"
mkdir -p "${source_root}"

if [[ ! -d "${helpers}/.git" ]]; then
  git clone https://github.com/TaceoLabs/circom-helpers.git "${helpers}"
fi
git -C "${helpers}" fetch --quiet origin main
git -C "${helpers}" checkout --quiet --detach 8aacd73ed6ab0a2b9b2158e613acfa920860865a
git -C "${helpers}" reset --quiet --hard 8aacd73ed6ab0a2b9b2158e613acfa920860865a

patch_file="${repo_root}/benchmarks/v1/circom/taceo-oprf/circom-helpers-graph-api.patch"
if rg -q 'self\.material\.graph\.nodes\(\)' "${helpers}/groth16-material/src/circom.rs"; then
  echo "helper graph API compatibility patch already applied"
elif git -C "${helpers}" apply --check "${patch_file}" >/dev/null 2>&1; then
  git -C "${helpers}" apply "${patch_file}"
else
  echo "helper source is neither pristine nor already compatible" >&2
  exit 1
fi

if [[ ! -d "${witness}/.git" ]]; then
  git clone https://github.com/philsippl/circom-witness-rs.git "${witness}"
fi
git -C "${witness}" fetch --quiet origin codex/remove-cxx-bridge-and-grep
git -C "${witness}" checkout --quiet --detach e11206a9f453145dcd6b814523cbfba4f60cf5c6
git -C "${witness}" reset --quiet --hard e11206a9f453145dcd6b814523cbfba4f60cf5c6
witness_patch="${repo_root}/benchmarks/v1/circom/taceo-oprf/circom-witness-rs-android-shift.patch"
if rg -q 'amount\.as_limbs\(\)\[0\] as usize' "${witness}/src/graph.rs"; then
  echo "witness branch Android shift compatibility patch already applied"
elif git -C "${witness}" apply --check "${witness_patch}" >/dev/null 2>&1; then
  git -C "${witness}" apply "${witness_patch}"
else
  echo "witness source is neither pristine nor already compatible" >&2
  exit 1
fi
printf '%s\n' "${helpers}"
