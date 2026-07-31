# ProveKit V1 cross-device benchmark campaign

This directory defines a reproducible 27-cell campaign: three workloads ×
three proof stacks × three targets. The primary Mac result is browser/WASM in
Google Chrome; Mac-native runs are smoke or diagnostic evidence only.

Read [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) before running anything.
Machine-readable policy lives in
[`benchmark-contract.json`](benchmark-contract.json), external source commits
in [`sources.lock.json`](sources.lock.json), and compiler/package versions in
[`toolchains.lock.json`](toolchains.lock.json).

## Publication matrix

| Stack | iPhone SE 2022 | Motorola E15 | M4 Max Chrome |
| --- | --- | --- | --- |
| ProveKit V1 | native C ABI/Mobench | native C ABI/Mobench | pinned V1 `tooling/provekit-wasm`, single-thread |
| Noir + Barretenberg | Mopro native | Mopro native, subject to ABI support | `noir_js` + smoke-validated `bb.js` |
| Circom + Groth16 | Mopro native | Mopro native | `snarkjs@0.7.6` |

Each stack runs Passport, WebAuthn, and OPRF, producing 27 logical cells. The
published semantic-parity freeze is complete: every cell has a proving-time,
proving-payload, proof-size, and peak-process-memory value. The canonical
sample file contains 162 records (one warmup and five measured proofs per
cell): [`semantic-parity-data/semantic-parity-samples.csv`](semantic-parity-data/semantic-parity-samples.csv).
The older [`data/benchmark-samples.csv`](data/benchmark-samples.csv) is retained
as the 2026-07-30 exploratory/compound-variant export and is not the V1
publication source.

The native Circom decision is recorded per row. Mopro is the mobile integration
layer; the iPhone uses Rapidsnark, while the 32-bit E15 uses the qualified
Arkworks or Rapidsnark path appropriate to the workload. The selected prover
and witness backend are explicit in the CSV. `iden3/circom-witnesscalc@0.3.0`
remains a compatibility fallback, not a publication backend.

### Publication snapshot

- **27 / 27 logical cells** passed the valid-proof, tamper-rejection,
  one-warmup/five-measured-sample contract.
- **162 CSV records:** 135 measured rows and 27 attested warmups.
- The four publication metrics are prove-only time, deduplicated proving
  payload, serialized proof bytes, and peak benchmark-process RSS.
- The semantic-parity export has no estimated V1 metrics. Its historical
  WebAuthn iPhone Circom row retains the explicit frozen zkey-plus-WTNS
  estimate note from the earlier campaign; it deliberately excludes IPA,
  XCUITest, and upload transport sizes. The older compound-variant export
  retains its separate five-row estimate annotations.

Use the CSV as the source of truth and keep that payload-estimate caveat in any
blog chart, caption, or comparison text.

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
sampling contract match exactly. The V1 exporter verifies the committed
evidence hashes and regenerates the canonical CSV idempotently:

```bash
bun benchmarks/v1/semantic-parity-data/export-v1.ts
bun test benchmarks/v1/semantic-parity-data/export.test.ts
```
