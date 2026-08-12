# Multithreaded Mac WASM campaign

The original `input-to-proof-samples.csv` Mac rows are a single-thread baseline.
This campaign is a separate, reproducible rerun of the same four semantic
profiles with Chrome workers enabled where the backend supports them:

| Stack | Witness generation | Proving |
| --- | --- | --- |
| ProveKit V1 | `noir_js@1.0.0-beta.11` (single) | V1 `provekit-wasm` + `wasm-bindgen-rayon` workers |
| Noir + Barretenberg | `noir_js@1.0.0-beta.19` (single) | `bb.js@4.2.0-aztecnr-rc.2` `WasmWorker` |
| Circom + Groth16 | `circom_runtime` WASM (single) | `snarkjs@0.7.6` Groth16 workers |

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
the witness/prover split. The campaign default is automatic worker sizing from
the browser's hardware-concurrency value; an explicit override is diagnostic
only and must not be mixed into the publication CSV. `noir_js` and stock Circom
witness calculation do not become multithreaded merely because the prover does;
the combined number is therefore an end-to-end measurement with single-thread
witness generation plus multithreaded proving.

There is one resource-aware exception: the large Circom WebAuthn zkey is run
with four SnarkJS workers on this host. Sixteen workers caused the Chrome
renderer to retain multiple multi-gigabyte copies of the zkey and did not
complete; the four-worker run is still genuinely multithreaded and records
`hardware_concurrency=4` in its raw report. It is not substituted with a
single-thread value. The smaller Circom profiles use Chrome's automatic
16-worker setting.

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
  INPUT_TO_PROOF_SERIES=passport_p1__mac_chrome__provekit_v1__warm_reuse \
  bun benchmarks/v1/scripts/run-mac-input-to-proof.ts

# Full 4-profile x 3-stack x cold/warm campaign.
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  INPUT_TO_PROOF_CAMPAIGN_ID=input-to-proof-v1-mac-multithread-20260812 \
  bun benchmarks/v1/scripts/run-mac-input-to-proof.ts

# Export a separate CSV; the historical single-thread CSV is not overwritten.
INPUT_TO_PROOF_EXECUTION_POLICY=multithread \
  INPUT_TO_PROOF_CAMPAIGN_ID=input-to-proof-v1-mac-multithread-20260812 \
  INPUT_TO_PROOF_OUTPUT_CSV=benchmarks/v1/input-to-proof-data/wasm-multithread-samples.csv \
  bun benchmarks/v1/input-to-proof-data/export.ts
```

The raw reports are written under
`target/v1-benchmarks/input-to-proof/mac-chrome-multithread/`. The exported
CSV uses the same sample-level schema as the canonical dataset and records the
execution policy in `artifact_version`, `package_versions`, and
`non_equivalence_note`; its raw report metadata is the authoritative source for
the effective worker configuration.
