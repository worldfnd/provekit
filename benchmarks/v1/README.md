# ProveKit V1 cross-device benchmark campaign

The Mac browser baseline in `input-to-proof-data/input-to-proof-samples.csv` is
single-threaded. The separate multithreaded Chrome rerun is documented in
[`MULTITHREADED_WASM.md`](./MULTITHREADED_WASM.md) and writes
`input-to-proof-data/wasm-multithread-samples.csv`; do not merge the two
execution policies when comparing results.

This directory defines the ProveKit V1 cross-device campaign. The canonical
publication dataset is the raw-input-to-proof export: four workloads × three
proof stacks × three targets × two timing modes, or 72 logical series. Its
freeze has 427 rows: 426 valid attempts across 71 complete series and one
structured E15 out-of-memory gap. The primary Mac surface is browser/WASM in
Google Chrome; Mac-native runs are smoke or diagnostic evidence only.

Read [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) before running anything.
Machine-readable policy lives in
[`benchmark-contract.json`](benchmark-contract.json), external source commits
in [`sources.lock.json`](sources.lock.json), and compiler/package versions in
[`toolchains.lock.json`](toolchains.lock.json).

## Publication matrix

| Stack | iPhone SE 2022 | Motorola E15 | M4 Max Chrome |
| --- | --- | --- | --- |
| ProveKit V1 | native C ABI/Mobench | native C ABI/Mobench | pinned V1 `tooling/provekit-wasm` (single-thread baseline and threaded rerun) |
| Noir + Barretenberg | Mopro native | Mopro native, subject to ABI support | `noir_js` + smoke-validated `bb.js` |
| Circom + Groth16 | Mopro native | Mopro native | `snarkjs@0.7.6` |

The canonical sample-level file is
[`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv).
It contains one warmup and five measured attempts for every successful timing
series, with raw input, witness generation, and serialized proof generation in
the headline boundary. The explicit E15 gap has blank metrics and hashed
failure evidence; no other target's value is substituted.

The earlier 27-cell proof-only export, the exploratory compound export, and
the TACEO production-backend candidate are retained under
[`legacy/`](legacy/README.md). They are useful historical/diagnostic evidence,
but none is a publication replacement for the canonical input-to-proof CSV.

## Input-to-proof campaign

The headline metric for the new campaign is raw input to serialized proof. It
includes fresh witness generation and proving, and excludes proof verification
and tamper rejection. The latter remain mandatory correctness gates.

The fourth workload is the exact Passport P1 pair:

- Noir: [`noir/passport_p1/src/main.nr`](noir/passport_p1/src/main.nr)
- Circom: [`circom/passport_p1/passport_p1.circom`](circom/passport_p1/passport_p1.circom)

`cold_local` uses a fresh process and proof runtime per attempt with locked
assets already local. `warm_reuse` reuses the initialized runtime, but still
regenerates the witness and proof for every attempt. The schema and exporter
live in [`input-to-proof-data/`](input-to-proof-data/); they preserve the old
CSV column order and append `timing_mode` and `input_to_proof_time_ms`.

On Mac, ProveKit uses the immutable V1 core commit
`9b2a6f37c67691eab4b0cec6c35e35c520e93285`; Barretenberg runs Noir execution
followed by proof generation; Circom runs `wtns.calculate` followed by Groth16
proof generation. Frozen witness files are correctness fixtures only and are
not accepted as input-to-proof measurements.

The Mac input-to-proof campaign is complete at 24 series / 144 rows,
including Passport P1 for all three stacks in both cold and warm modes. Native
iPhone execution uses one 1+5 warm session per function. Its cold session
relaunches the app six times, retaining downloaded hash-verified assets but
creating a fresh process and proof runtime for every attempt; launch zero is
the warmup and launches one through five are measured samples. The exact native export contract is in
[`input-to-proof-data/README.md`](input-to-proof-data/README.md).
The separate Marimo analysis is
[`analysis/input_to_proof_analysis.py`](analysis/input_to_proof_analysis.py);
it reads only the canonical input-to-proof CSV and keeps every figure in its
own cell.

The multithreaded Mac-only rerun is exported separately as
[`input-to-proof-data/wasm-multithread-samples.csv`](input-to-proof-data/wasm-multithread-samples.csv).
It has the same 41-column sample schema and 144 rows, but must not be merged
with the single-thread CSV. ProveKit uses eight Rayon workers, Barretenberg
uses its 16-worker host-effective pool, and Circom uses 16 SnarkJS workers for
the smaller profiles. The large Circom WebAuthn key is capped at four workers
because the 16-worker Chrome renderer did not complete within the host memory
budget; this is recorded in its raw report and remains a multithreaded result.

The native Circom decision is recorded per row. Mopro is the mobile integration
layer; the iPhone uses Rapidsnark, while the 32-bit E15 uses the qualified
Arkworks or Rapidsnark path appropriate to the workload. The selected prover
and witness backend are explicit in the CSV. `iden3/circom-witnesscalc@0.3.0`
remains a compatibility fallback, not a publication backend.

The E15 input-to-proof freeze has 23 successful logical series. The final
WebAuthn/Circom cold series is retained as a structured `runtime_failed` gap
with failure code `out_of_memory`: Rapidsnark could not map the 1.73 GB zkey
and WTNS in the device's 32-bit address space. Its null metrics and hashed
evidence are recorded in
[`input-to-proof-data/e15-webauthn-cold-gap.json`](input-to-proof-data/e15-webauthn-cold-gap.json);
no other device's value is substituted.

For the iPhone OPRF input-to-proof lane, `wasmi@0.46.0` interprets the exact
Circom witness Wasm and Rapidsnark proves the resulting WTNS. This replaces the
layout-sensitive Rust-Witness AOT artifact that crashed on iOS; the interpreted
witness was qualified byte-for-byte against the frozen SnarkJS WTNS. Other
native iPhone Circom lanes retain their locked Rust-Witness generators.

### Publication snapshot

- **72 logical timing series** are expected; **71** completed with one warmup
  and five measured attempts, while one E15 Circom/WebAuthn cold series is an
  explicit `runtime_failed` / `out_of_memory` gap.
- **427 CSV records:** 355 measured rows, 71 attested warmups, and one gap row.
- The four publication metrics are input-to-proof time, deduplicated proving
  payload, serialized proof bytes, and peak benchmark-process RSS.
- The canonical export contains no estimated metrics. Historical estimates
  and proof-only boundaries remain labeled in `legacy/` and must not be mixed
  into the input-to-proof charts.

## These are counterparts, not identical circuits

The campaign compares the closest practical implementation of a workload.
Results must include the circuit name and may not be presented as a pure
proof-system ranking.

- Passport: Noir `complete_age_check` is monolithic. Self Circom uses a
  signature-specific registration circuit plus `vc_and_disclose`.
- WebAuthn: the Noir ES256 assertion binds the challenge, ceremony type,
  origin, RP-ID hash, UP/UV flags, signature, and public key.
  `privacy-ethereum/webauth-circom` is the closest Circom counterpart but does
  not bind the complete same statement. This corrects the older claim that no
  usable Circom WebAuthn counterpart existed.
- OPRF: TACEO `oprf-nr` is a core Noir example. World ID Protocol provides
  application query and nullifier Circom circuits. Report those circuits under
  separate names.

## Sampling and correctness

Every runnable cell performs one warmup followed by five sequential measured
samples. Before timing, the lane must accept a valid proof, reject a tampered
proof, and retain its public outputs and workload identity.

Native and browser results are separate runtime categories. Missing metrics
are blank, not zero. Use `unsupported`, `build_failed`, `crashed`,
`timed_out`, or `zero_samples` with a structured failure message. Raw logs may
contain operational evidence, but exports must remain secret-free.

## Entry point

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage all \
  --campaign provekit-v1-cross-device --dry-run
```

Supported stages are `bootstrap`, `prepare`, `smoke`, `measure`, `export`, and
`all`. Always run the dry plan first. BrowserStack credentials remain external,
and paid sessions require the runner's explicit confirmation flag.

Generated sources, bundles, raw results, and logs live under
`target/v1-benchmarks/`; they are not source-controlled. A preparation freezes
one content-addressed campaign manifest. ProveKit preparation may be
nondeterministic, so all targets must reuse the frozen bundle rather than
expecting an independently prepared bundle to have identical bytes.

Historical files and measurements elsewhere in this directory are diagnostic
inputs only. They enter this campaign only when their source commit, package
versions, circuit identity, device/runtime identity, bundle hashes, and 1+5
sampling contract match exactly. The input-to-proof exporter verifies the
committed evidence hashes and regenerates the canonical CSV idempotently:

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
```

The proof-only and TACEO exporters remain runnable as historical diagnostics;
their outputs are written under `legacy/` and never overwrite the canonical
file. See [`legacy/README.md`](legacy/README.md) for the exact provenance and
the reason the campaign was rerun.
