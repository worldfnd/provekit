#!/usr/bin/env bash
set -euo pipefail

if [[ "${MOBENCH_CI_PREPARE:-}" != "1" ]]; then
  echo "MOBENCH_CI_PREPARE=1 is required to prepare browser benchmarks" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
generated_dir="${repo_root}/bench-mobile/generated/wasm"

"${repo_root}/bench-mobile/scripts/generate-fixtures.sh"
mkdir -p "${generated_dir}"

export_witness() {
  local program_path="$1"
  local input_path="$2"
  local output_name="$3"
  cargo run --release -p bench-mobile --example export-wasm-witness -- \
    "${repo_root}/${program_path}" \
    "${repo_root}/${input_path}" \
    "${generated_dir}/${output_name}.witness.postcard"
}

export_witness \
  noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json \
  noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml \
  complete_age_check
export_witness \
  noir-examples/noir-passport/merkle_age_check/target/t_add_dsc_720.json \
  noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_add_dsc_720.toml \
  t_add_dsc_720
export_witness \
  noir-examples/noir-passport/merkle_age_check/target/t_add_id_data_720.json \
  noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_add_id_data_720.toml \
  t_add_id_data_720
export_witness \
  noir-examples/noir-passport/merkle_age_check/target/t_add_integrity_commit.json \
  noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_add_integrity_commit.toml \
  t_add_integrity_commit
export_witness \
  noir-examples/noir-passport/merkle_age_check/target/t_attest.json \
  noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_attest.toml \
  t_attest
export_witness \
  benchmarks/v1/noir/webauthn_assertion/target/webauthn_assertion.json \
  benchmarks/v1/noir/webauthn_assertion/Prover.toml \
  webauthn_assertion
export_witness \
  noir-examples/oprf/target/oprf.json \
  noir-examples/oprf/Prover.toml \
  oprf

python3 - "${repo_root}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = root / "Cargo.toml"
text = manifest.read_text()
old = 'provekit-prover = { path = "provekit/prover", version = "1.0.0" }'
new = (
    'provekit-prover = { path = "provekit/prover", version = "1.0.0", '
    'default-features = false }'
)
if text.count(old) != 1:
    raise SystemExit("unexpected provekit-prover workspace dependency")
text = text.replace(old, new)
for member in (
    "tooling/cli",
    "tooling/provekit-bench",
    "tooling/provekit-ffi",
    "tooling/provekit-gnark",
    "tooling/provekit-wasm",
    "tooling/verifier-server",
):
    entry = f'  "{member}",\n'
    if text.count(entry) != 1:
        raise SystemExit(f"unexpected ProveKit workspace member: {member}")
    text = text.replace(entry, "")
manifest.write_text(text)

bench_manifest = root / "bench-mobile/Cargo.toml"
text = bench_manifest.read_text()
old = '[lib]\ncrate-type = ["lib", "cdylib", "staticlib"]'
new = '[lib]\npath = "src/lib_web.rs"\ncrate-type = ["lib", "cdylib", "staticlib"]'
if text.count(old) != 1:
    raise SystemExit("unexpected bench-mobile lib target")
text = text.replace(old, new)
old = "default = []\n"
new = 'default = ["web-passport-complete"]\n'
if text.count(old) != 1:
    raise SystemExit("unexpected bench-mobile default features")
text = text.replace(old, new)
old = "provekit-prover.workspace = true\n"
if text.count(old) != 1:
    raise SystemExit("unexpected bench-mobile prover dependency")
text = text.replace(old, "")
text += (
    '\n[target.\'cfg(not(target_arch = "wasm32"))\'.dependencies]\n'
    'provekit-prover = { workspace = true, features = ["witness-generation", "parallel"] }\n'
    '\n[target.\'cfg(target_arch = "wasm32")\'.dependencies]\n'
    'provekit-prover.workspace = true\n'
)
bench_manifest.write_text(text)
PY

# Mobench 0.1.48's browser runtime uses the wasm-bindgen 0.2.113 family.
# Removing unrelated server/tooling workspace members above releases their
# older exact js-sys pins so the browser crate can resolve the matching family.
cargo update -p js-sys --precise 0.3.90
