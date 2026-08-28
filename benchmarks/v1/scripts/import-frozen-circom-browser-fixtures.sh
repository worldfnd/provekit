#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source_root="${CIRCOM_FROZEN_SOURCE_ROOT:-}"
destination="${CIRCOM_BROWSER_FIXTURE_ROOT:-${repo_root}/target/v1-benchmarks/circom-browser}"

if [[ -z "${source_root}" ]]; then
  echo "error: set CIRCOM_FROZEN_SOURCE_ROOT to a verified prior target/v1-benchmarks directory" >&2
  exit 1
fi

source_root="$(cd "${source_root}" && pwd)"
mkdir -p "${destination}"/{passport,webauthn}

link_verified() {
  local expected_sha="$1"
  local source_file="$2"
  local destination_file="$3"
  local actual_sha

  if [[ ! -f "${source_file}" ]]; then
    echo "error: missing frozen artifact ${source_file}" >&2
    exit 1
  fi
  actual_sha="$(shasum -a 256 "${source_file}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "error: hash drift for ${source_file}" >&2
    echo "expected ${expected_sha}" >&2
    echo "actual   ${actual_sha}" >&2
    exit 1
  fi
  ln -f "${source_file}" "${destination_file}"
}

self_register="register_sha256_sha256_sha256_rsa_65537_4096"
link_verified \
  b59b4c36d213a68cff17049353c7c000bd0fb929ce614ae5ff44e12281a19a14 \
  "${source_root}/circom/self/${self_register}/${self_register}_js/${self_register}.wasm" \
  "${destination}/passport/${self_register}.wasm"
link_verified \
  761a903ee3218cd0f986b7c8b9c46aac4cd5c2107e7cd0c2daf3b80f9c336d31 \
  "${source_root}/mobile-fixtures/groth16/${self_register}/resources/proving_key.zkey" \
  "${destination}/passport/${self_register}.zkey"
link_verified \
  2ef5733c2634cf753b969640bb23e4e590b935fcd5cedfac1241184885fece3e \
  "${source_root}/mobile-fixtures/groth16/${self_register}/resources/verification_key.json" \
  "${destination}/passport/${self_register}.vkey.json"
link_verified \
  2d9ccff0b1a94c500d722cea20fbeb68ff9c6c48f21391b7f5b441752dfa5030 \
  "${source_root}/mobile-fixtures/groth16/${self_register}/resources/input.json" \
  "${destination}/passport/${self_register}.input.json"

link_verified \
  cb300197503318ab2635499d4b44f46f932e311930faabf6be960d6d81110f13 \
  "${source_root}/circom/self/vc_and_disclose/vc_and_disclose_js/vc_and_disclose.wasm" \
  "${destination}/passport/vc_and_disclose.wasm"
link_verified \
  4ef28839cb7d9081cd0d747abd5a443d1a9962432c8469076d3c49107b59c964 \
  "${source_root}/mobile-fixtures/groth16/vc_and_disclose/resources/proving_key.zkey" \
  "${destination}/passport/vc_and_disclose.zkey"
link_verified \
  b5c877411b38a5f1257280a9f7edc586234c5cea6b1f58a5e29fc31c025addd0 \
  "${source_root}/mobile-fixtures/groth16/vc_and_disclose/resources/verification_key.json" \
  "${destination}/passport/vc_and_disclose.vkey.json"
link_verified \
  f88d57881fdf0569ab5896a7bbbb96c6fb463962bafa58c20f11b1b44061a011 \
  "${source_root}/mobile-fixtures/groth16/vc_and_disclose/resources/input.json" \
  "${destination}/passport/vc_and_disclose.input.json"

link_verified \
  b24b95ec8d9eca43e6d14d0f0d1a9d426ce2dded1855b13a765d6ceb281e2088 \
  "${source_root}/circom/webauthn/webauthn_default_js/webauthn_default.wasm" \
  "${destination}/webauthn/webauthn_default.wasm"
link_verified \
  a5828d55680b65b55a1bb5be0a26f151342e37551537a71d257fe07d9677e94b \
  "${source_root}/groth16/webauthn/webauthn_default_benchmark.zkey" \
  "${destination}/webauthn/webauthn_default.zkey"
link_verified \
  4c83de54945e7987e3072d496d363e2256e767905f99106f84da66330ed42802 \
  "${source_root}/groth16/webauthn/verification_key.json" \
  "${destination}/webauthn/webauthn_default.vkey.json"
link_verified \
  b635e9511a747bb0bea0278d423e3e859b24d386368186c72a8e46e4e0644657 \
  "${source_root}/sources/webauth-circom/scripts/input_webauthn_default.json" \
  "${destination}/webauthn/webauthn_default.input.json"

jq -n '{
  schema_version: 1,
  fixtures: {
    passport: [
      {
        circuit: "register_sha256_sha256_sha256_rsa_65537_4096",
        variant: "self_passport_registration",
        wasm: "passport/register_sha256_sha256_sha256_rsa_65537_4096.wasm",
        zkey: "passport/register_sha256_sha256_sha256_rsa_65537_4096.zkey",
        verification_key: "passport/register_sha256_sha256_sha256_rsa_65537_4096.vkey.json",
        input: "passport/register_sha256_sha256_sha256_rsa_65537_4096.input.json",
        circuit_commit: "15b167e3543a9dff1dbb16fcf71a45fe4625cf9e",
        semantic_equivalence: "closest-analogue-not-equivalent"
      },
      {
        circuit: "vc_and_disclose",
        variant: "self_passport_disclosure",
        wasm: "passport/vc_and_disclose.wasm",
        zkey: "passport/vc_and_disclose.zkey",
        verification_key: "passport/vc_and_disclose.vkey.json",
        input: "passport/vc_and_disclose.input.json",
        circuit_commit: "15b167e3543a9dff1dbb16fcf71a45fe4625cf9e",
        semantic_equivalence: "closest-analogue-not-equivalent"
      }
    ],
    webauthn: [
      {
        circuit: "webauthn_default",
        variant: "privacy_ethereum_webauth_circom",
        wasm: "webauthn/webauthn_default.wasm",
        zkey: "webauthn/webauthn_default.zkey",
        verification_key: "webauthn/webauthn_default.vkey.json",
        input: "webauthn/webauthn_default.input.json",
        circuit_commit: "0fb5b4aa1398281c2fd3dbe14db147e05b61f201",
        semantic_equivalence: "closest-analogue-not-equivalent"
      }
    ],
    oprf: []
  }
}' >"${destination}/manifest.json"

echo "Imported hash-verified Circom browser fixtures into ${destination}"
