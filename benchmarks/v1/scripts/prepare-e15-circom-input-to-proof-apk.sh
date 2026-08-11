#!/usr/bin/env bash

set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: $0 <oprf|nullifier|webauthn|passport-p1|passport-disclose|passport-register>" >&2
  exit 2
}

workload="$1"
[[ "${workload}" != "nullifier" ]] || workload="oprf"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
template="${repo_root}/target/v1-benchmarks/e15-noir-barretenberg-armv7-build/android"
library_root="${repo_root}/target/v1-benchmarks/input-to-proof/e15/circom-armv7-libs"
output="${repo_root}/target/v1-benchmarks/e15-circom-${workload}-input-to-proof-build/android"

case "${workload}" in
  oprf)
    library="${library_root}/oprf-nullifier.so"
    zkey="${repo_root}/benchmarks/v1/circom/web/dist/assets/oprf/oprf_nullifier.zkey"
    witness="${repo_root}/target/v1-benchmarks/circom/oprf/oprf_nullifier.wtns"
    vkey="${repo_root}/target/v1-benchmarks/rapidsnark-oprf-nullifier-ios/ios/BenchRunner/BenchRunner/Resources/verification_key.json"
    package_suffix="rapidsnarkoprfinputtoproof"
    ;;
  webauthn)
    library="${library_root}/webauthn.so"
    zkey="${repo_root}/target/v1-benchmarks/groth16/webauthn/webauthn_default_benchmark.zkey"
    witness="${repo_root}/target/v1-benchmarks/circom/webauthn/fixture.wtns"
    vkey="${repo_root}/target/v1-benchmarks/groth16/webauthn/verification_key.json"
    package_suffix="rapidsnarkwebauthninputtoproof"
    ;;
  passport-p1)
    library="${library_root}/passport-p1.so"
    zkey="${repo_root}/target/v1-benchmarks/groth16/passport_p1/passport_p1_final.zkey"
    witness="${repo_root}/target/v1-benchmarks/circom-witnesses/passport_p1/native.wtns"
    vkey="${repo_root}/target/v1-benchmarks/groth16/passport_p1/verification_key.json"
    package_suffix="rapidsnarkpassportp1inputtoproof"
    ;;
  passport-disclose)
    library="${library_root}/passport-disclose.so"
    zkey="${repo_root}/benchmarks/v1/circom/web/dist/assets/passport/vc_and_disclose.zkey"
    witness="${repo_root}/target/v1-benchmarks/circom/passport/vc_and_disclose.wtns"
    vkey="${repo_root}/target/v1-benchmarks/groth16/passport-disclose-verification-key.json"
    package_suffix="rapidsnarkpassportdiscloseinputtoproof"
    ;;
  passport-register)
    library="${library_root}/passport-register.so"
    zkey="${repo_root}/benchmarks/v1/circom/web/dist/assets/passport/register_sha256_sha256_sha256_rsa_65537_4096.zkey"
    witness="${repo_root}/target/v1-benchmarks/circom/passport/register_sha256_sha256_sha256_rsa_65537_4096.wtns"
    vkey="${repo_root}/target/v1-benchmarks/groth16/passport-register-verification-key.json"
    package_suffix="rapidsnarkpassportregisterinputtoproof"
    ;;
  *)
    echo "unknown workload: ${workload}" >&2
    exit 2
    ;;
esac

for file in "${library}" "${zkey}" "${witness}"; do
  [[ -f "${file}" ]] || {
    echo "missing fixture: ${file}" >&2
    exit 1
  }
done

helper=""
if [[ "${workload}" == "webauthn" ]]; then
  helper="${library_root}/webauthn-witness.so"
  [[ -f "${helper}" ]] || {
    echo "missing WebAuthn witness helper: ${helper}" >&2
    exit 1
  }
fi

if [[ ! -f "${vkey}" ]]; then
  mkdir -p "$(dirname "${vkey}")"
  "${repo_root}/benchmarks/v1/circom/web/node_modules/.bin/snarkjs" zkey export verificationkey \
    "${zkey}" "${vkey}"
fi

rsync -a --delete \
  --exclude app/build \
  --exclude .gradle \
  --exclude app/src/main/jniLibs \
  "${template}/" "${output}/"

jni="${output}/app/src/main/jniLibs/armeabi-v7a"
mkdir -p "${jni}"
copy_fixture() {
  cp -c "$1" "$2" 2>/dev/null || cp "$1" "$2"
}
copy_fixture "${library}" "${jni}/libprovekit_v1_mobile_adapters.so"
copy_fixture "${template}/app/src/main/jniLibs/armeabi-v7a/libc++_shared.so" "${jni}/libc++_shared.so"
copy_fixture "${zkey}" "${jni}/libmobench_proving_key.so"
copy_fixture "${witness}" "${jni}/libmobench_reference_wtns.so"
copy_fixture "${vkey}" "${jni}/libmobench_verification_key.so"
if [[ -n "${helper}" ]]; then
  copy_fixture "${helper}" "${jni}/libmobench_witness.so"
fi

gradle="${output}/app/build.gradle"
perl -0pi -e \
  's/applicationId "[^"]+"/applicationId "dev.world.provekitv1mobileadapters.'"${package_suffix}"'"/' \
  "${gradle}"
perl -0pi -e \
  's#"\*\*/libmobench_witness\.so",#"**/libmobench_witness.so",\n                "**/libmobench_reference_wtns.so",\n                "**/libmobench_verification_key.so",#' \
  "${gradle}"

export JAVA_HOME="${JAVA_HOME:-${HOME}/.local/share/mise/installs/java/temurin-21.0.11+10.0.LTS}"
(cd "${output}" && ./gradlew assembleDebug)

app="${output}/app/build/outputs/apk/debug/app-debug.apk"
[[ -f "${app}" ]] || {
  echo "missing built APK: ${app}" >&2
  exit 1
}
shasum -a 256 "${app}"
