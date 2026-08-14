# Multithreaded Mac WASM campaign

The original `input-to-proof-samples.csv` Mac rows are a single-thread baseline.
The earlier `wasm-multithread-samples.csv` export used ProveKit's automatic
eight-worker pool and a four-worker resource cap for Circom WebAuthn. The
fixed-thread campaign described below is a separate rerun with exactly 16
requested workers for ProveKit and SnarkJS, including WebAuthn.

| Stack | Witness generation | Proving |
| --- | --- | --- |
| ProveKit V1 | `noir_js@1.0.0-beta.11` (single) | V1 `provekit-wasm` + `wasm-bindgen-rayon` (16 workers) |
| Noir + Barretenberg | `noir_js@1.0.0-beta.19` (single) | `bb.js@4.2.0-aztecnr-rc.2` `WasmWorker` |
| Circom + Groth16 | `circom_runtime` WASM (single) | `snarkjs@0.7.6` Groth16 workers (16 workers) |

All rows are input-to-serialized-proof measurements. Each warm series has one
warmup and five measured samples. Each cold series uses six fresh Chrome
profiles, with the first attempt retained as the warmup. Proof verification
and tampered-proof rejection remain correctness gates and are not silently
substituted with timings from the single-thread baseline.

## Threading boundary

`SharedArrayBuffer` and `crossOriginIsolated` are required. The local benchmark
servers send `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`. Reports record the browser's
`navigator.hardwareConcurrency`, requested thread policy, worker backend, and
the witness/prover split. This fixed-thread campaign requests exactly 16
workers for ProveKit and SnarkJS; the raw reports record the effective count
and any browser/runtime failure. `noir_js` and stock Circom witness calculation
do not become multithreaded merely because the prover does; the combined number
is therefore an end-to-end measurement with single-thread witness generation
plus multithreaded proving. Barretenberg remains at its existing 32-requested,
16-effective configuration.

ProveKit V1 is built from the pinned V1 core commit and its local WASM package,
not from the current `@worldcoin/provekit` npm package. The npm package has a
threaded API, but its current beta.20/PKP-2 artifacts are incompatible with the
V1 beta.11/PKP-1 artifacts used here.

## Run

From the repository root:

```bash
# Build the three browser fixtures with their worker assets.
bash benchmarks/v1/barretenberg/web/build.sh
bash benchmarks/v1/circom/web/build.sh
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  bash benchmarks/v1/wasm/scripts/build.sh

# First run one smoke per stack/profile (one warmup + one sample).
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  MOBENCH_WASM_THREADS=16 MOBENCH_SNARKJS_THREADS=16 \
  INPUT_TO_PROOF_SERIES=passport_p1__mac_chrome__provekit_v1__warm_reuse \
  bun benchmarks/v1/scripts/run-mac-input-to-proof.ts

# Full 4-profile x 3-stack x cold/warm fixed-16 campaign.
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  MOBENCH_WASM_THREADS=16 MOBENCH_SNARKJS_THREADS=16 \
  INPUT_TO_PROOF_CAMPAIGN_ID=input-to-proof-v1-mac-multithread-16-20260812 \
  INPUT_TO_PROOF_OUTPUT_ROOT=target/v1-benchmarks/input-to-proof/mac-chrome-multithread-16 \
  bun benchmarks/v1/scripts/run-mac-input-to-proof.ts

# Export a separate fixed-16 CSV; neither historical CSV is overwritten.
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  INPUT_TO_PROOF_CAMPAIGN_ID=input-to-proof-v1-mac-multithread-16-20260812 \
  INPUT_TO_PROOF_RAW_ROOT=target/v1-benchmarks/input-to-proof/mac-chrome-multithread-16 \
  INPUT_TO_PROOF_OUTPUT_CSV=benchmarks/v1/input-to-proof-data/wasm-multithread-16-samples.csv \
  bun benchmarks/v1/input-to-proof-data/export.ts

# Replace only the Mac rows in the full CSV; retain the exact iPhone/E15 rows
# and their original campaign provenance.
bun benchmarks/v1/input-to-proof-data/merge-mac-fixed16.ts
```

The fixed-16 raw reports are written under
`target/v1-benchmarks/input-to-proof/mac-chrome-multithread-16/`. The exported
CSV uses the same sample-level schema as the canonical dataset and records the
execution policy in `artifact_version`, `package_versions`, and
`non_equivalence_note`; its raw report metadata is the authoritative source for
the effective worker configuration. This run has 22 complete series (132
sample rows) and two explicit Circom WebAuthn gap rows: the 16-worker cold
renderer stalled under memory pressure, so warm reuse was not started. The
earlier four-worker WebAuthn result is retained only in the automatic-thread
diagnostic dataset. The merge command above makes this fixed-16 Mac result the
Mac portion of `input-to-proof-samples.csv` while leaving mobile evidence
unchanged.
