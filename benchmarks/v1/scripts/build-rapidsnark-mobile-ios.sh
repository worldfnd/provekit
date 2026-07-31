#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <passport-disclose|passport-register>" >&2
}

[[ $# -eq 1 ]] || {
  usage
  exit 2
}

workload="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
benchmark_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${benchmark_root}/../.." && pwd)"

case "${workload}" in
  passport-disclose)
    crate="${benchmark_root}/rapidsnark-mobile"
    fixture="${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16/vc_and_disclose"
    output="${repo_root}/target/v1-benchmarks/rapidsnark-disclose-ios"
    ;;
  passport-register)
    crate="${benchmark_root}/rapidsnark-mobile-register"
    fixture="${repo_root}/target/v1-benchmarks/mobile-fixtures/groth16/register_sha256_sha256_sha256_rsa_65537_4096"
    output="${repo_root}/target/v1-benchmarks/rapidsnark-register-ios"
    ;;
  *)
    usage
    exit 2
    ;;
esac

for command in cargo-mobench cp xcodegen; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done

for resource in proving_key.zkey reference.wtns verification_key.json; do
  [[ -f "${fixture}/resources/${resource}" ]] || {
    echo "error: missing ${fixture}/resources/${resource}" >&2
    exit 1
  }
done

"${script_dir}/build-rapidsnark-ios-libs.sh" >/dev/null

expected_crate="$(
  sed -n 's/^name = "\(.*\)"/\1/p' "${crate}/Cargo.toml" |
    head -1 |
    tr - _
)"
expected_function="${expected_crate}::bench_passport_rapidsnark_prove"
function_list="$(cargo-mobench list --crate-path "${crate}")"
grep -F "${expected_function}" <<<"${function_list}" >/dev/null || {
    echo "error: Mobench did not discover ${expected_function}" >&2
    exit 1
  }

cargo-mobench build \
  --target ios \
  --release \
  --ios-deployment-target 15.0 \
  --crate-path "${crate}" \
  --output-dir "${output}" \
  --progress

project="${output}/ios/BenchRunner"
resources="${project}/BenchRunner/Resources"
case "${resources}" in
  "${repo_root}"/target/v1-benchmarks/*/ios/BenchRunner/BenchRunner/Resources)
    rm -rf "${resources}"
    ;;
  *)
    echo "error: refusing to clean unexpected resource path: ${resources}" >&2
    exit 1
    ;;
esac
mkdir -p "${resources}"
for resource in proving_key.zkey reference.wtns verification_key.json; do
  # APFS clone copies keep staging fast while presenting ordinary files to
  # Xcode. Fall back to a regular copy on filesystems without clone support.
  cp -c "${fixture}/resources/${resource}" "${resources}/${resource}" 2>/dev/null ||
    cp "${fixture}/resources/${resource}" "${resources}/${resource}"
done

(
  cd "${project}"
  xcodegen generate
)

cargo-mobench package-ipa \
  --method adhoc \
  --crate-path "${crate}" \
  --output-dir "${output}" \
  --yes \
  --non-interactive
cargo-mobench package-xcuitest \
  --crate-path "${crate}" \
  --output-dir "${output}" \
  --yes \
  --non-interactive

ipa="${output}/ios/BenchRunner.ipa"
test_bundle="${output}/ios/BenchRunnerUITests.zip"
[[ -f "${ipa}" ]] || {
  echo "error: package did not produce ${ipa}" >&2
  exit 1
}
[[ -f "${test_bundle}" ]] || {
  echo "error: package did not produce ${test_bundle}" >&2
  exit 1
}

"${script_dir}/patch-ios15-xcuitest-suite.sh" "${test_bundle}"
shasum -a 256 "${ipa}" "${test_bundle}"
