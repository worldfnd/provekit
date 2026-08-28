#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"
source_root="${V1_BENCHMARK_SOURCE_ROOT:-${repo_root}/target/v1-benchmarks/sources}"
compat_root="${V1_NOIR_BETA19_COMPAT_ROOT:-${repo_root}/target/v1-benchmarks/noir-beta19-compat}"
world_vendor="${source_root}/world-id-protocol/crates/proof/noir/passkey-ownership-proof/vendor"
poseidon_source="${source_root}/noir-poseidon"
passport_poseidon_source="${source_root}/noir-poseidon-v0.3.0"
passport_bignum_source="${source_root}/noir-bignum-v0.10.0"
passport_rsa_source="${source_root}/noir-rsa-v0.11.0"

"${script_dir}/bootstrap-sources.sh" >/dev/null

for required in \
  "${world_vendor}/webauthn/Nargo.toml" \
  "${poseidon_source}/Nargo.toml" \
  "${passport_poseidon_source}/Nargo.toml" \
  "${passport_bignum_source}/Nargo.toml" \
  "${passport_rsa_source}/Nargo.toml"; do
  [[ -f "${required}" ]] || {
    echo "error: missing pinned compatibility input ${required}" >&2
    exit 1
  }
done

case "${compat_root}" in
  "${repo_root}"/target/v1-benchmarks/noir-beta19-compat)
    rm -rf "${compat_root}"
    ;;
  *)
    echo "error: refusing to replace unexpected compatibility path ${compat_root}" >&2
    exit 1
    ;;
esac
mkdir -p "${compat_root}"
cp -R "${world_vendor}" "${compat_root}/vendor"
cp -R "${poseidon_source}" "${compat_root}/poseidon"
mkdir -p "${compat_root}/passport"
cp -R "${passport_poseidon_source}" "${compat_root}/passport/poseidon"
cp -R "${passport_bignum_source}" "${compat_root}/passport/noir-bignum"
cp -R "${passport_rsa_source}" "${compat_root}/passport/noir-rsa"
rm -rf "${compat_root}/poseidon/.git"

for package in noir-bignum-mavros noir_bigcurve-mavros; do
  manifest="${compat_root}/vendor/${package}/Nargo.toml"
  grep -F 'poseidon = { git = "https://github.com/noir-lang/poseidon", tag = "v0.2.6" }' \
    "${manifest}" >/dev/null || {
    echo "error: expected ${package} Poseidon pin is missing" >&2
    exit 1
  }
  perl -0pi -e \
    's#poseidon = \{ git = "https://github\.com/noir-lang/poseidon", tag = "v0\.2\.6" \}#poseidon = { path = "../../poseidon" }#g' \
    "${manifest}"
done

offset_file="${compat_root}/vendor/noir_bigcurve-mavros/src/utils/derive_offset_generators.nr"
grep -F 'let cofactor_bits: [u1; 128] = cofactor.to_be_bits();' \
  "${offset_file}" >/dev/null || {
  echo "error: expected cofactor bit declaration is missing" >&2
  exit 1
}
grep -F 'crate::poseidon2_permutation(state, 4)' \
  "${compat_root}/poseidon/src/poseidon2.nr" >/dev/null || {
  echo "error: pinned Poseidon source is not Noir beta.19 compatible" >&2
  exit 1
}

passport_poseidon="${compat_root}/passport/poseidon/src/poseidon2.nr"
perl -0pi -e \
  's/crate::poseidon2_permutation\(self\.state\)/crate::poseidon2_permutation(self.state, 4)/g; s/crate::poseidon2_permutation\(state\)/crate::poseidon2_permutation(state, 4)/g' \
  "${passport_poseidon}"
grep -F 'crate::poseidon2_permutation(state, 4)' "${passport_poseidon}" >/dev/null || {
  echo "error: failed to prepare Passport Poseidon beta.19 compatibility source" >&2
  exit 1
}

perl -0pi -e \
  's#poseidon = \{ git = "https://github\.com/noir-lang/poseidon", tag = "v0\.3\.0" \}#poseidon = { path = "../poseidon" }#g' \
  "${compat_root}/passport/noir-bignum/Nargo.toml"
perl -0pi -e \
  's#bignum = \{tag = "v0\.10\.0", git = "https://github\.com/noir-lang/noir-bignum"\}#bignum = { path = "../noir-bignum" }#g' \
  "${compat_root}/passport/noir-rsa/Nargo.toml"
grep -F 'poseidon = { path = "../poseidon" }' \
  "${compat_root}/passport/noir-bignum/Nargo.toml" >/dev/null
grep -F 'bignum = { path = "../noir-bignum" }' \
  "${compat_root}/passport/noir-rsa/Nargo.toml" >/dev/null

find "${compat_root}" -name .git -type d -prune -exec rm -rf {} +
echo "Prepared deterministic Noir beta.19 WebAuthn overlay at ${compat_root}"
