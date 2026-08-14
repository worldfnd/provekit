# ProveKit V1 input-to-proof benchmarks

This directory is the reproducible publication campaign for ProveKit V1. It
measures the complete client-side path from a frozen structured input through
witness generation and proving to serialized proof bytes across three stacks,
three execution targets, and cold/warm runtime modes.

The canonical publication artifact is
[`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv).
The reproducibility contract, version pins, device requirements, correctness
gates, and gap policy are in
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

> **Publication snapshot:** 417 rows, 72 logical series, 4 profiles × 3 stacks
> × 3 targets × 2 timing modes. There are 345 measured samples, 69 warmups,
> and 3 explicit gaps. Missing metrics are blank, never zero or substituted.

## Start here

| I need to… | Use |
| --- | --- |
| Reproduce the campaign | [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) |
| Inspect the canonical data | [`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv) |
| Validate or export rows | [`input-to-proof-data/`](input-to-proof-data/) |
| Check immutable source pins | [`sources.lock.json`](sources.lock.json) and [`toolchains.lock.json`](toolchains.lock.json) |
| Inspect the matrix and gap contract | [`benchmark-contract.json`](benchmark-contract.json) |
| Review superseded experiments | [`legacy/README.md`](legacy/README.md) |

## Campaign matrix

| Stack | iPhone SE 2022 | Motorola E15 | M4 Max MacBook |
| --- | --- | --- | --- |
| ProveKit V1 | Native Mobench / WHIR | Native Mobench / WHIR | Chrome/WASM, fixed 16 workers |
| Noir + Barretenberg | Mopro native | Mopro native where qualified | Chrome/WASM, 16 effective workers |
| Circom + Groth16 | Mopro native / Rapidsnark | Mopro native with target-specific evidence | Chrome/WASM / SnarkJS, 16 workers |

The Mac publication surface is Chrome/WASM. Mac-native runs are diagnostic
only. BrowserStack credentials and paid-session confirmation stay outside the
repository. Native and browser rows remain separate runtime categories.

## Measurement contract

The headline boundary is:

```text
raw structured input → witness generation → proof generation → serialized proof bytes
```

Each successful series contains one warmup followed by five sequential measured
samples. Cold mode starts a fresh process/runtime for each attempt with locked
assets already local. Warm mode reuses initialized runtime state while
regenerating the witness and proof for every attempt.

Every runnable lane must accept a valid proof and reject a tampered proof before
its timings are exported. The CSV also records phase timings where a backend
exposes them, exact proof bytes, deduplicated proving payload size, peak process
RSS, constraints, package/source identities, artifact hashes, and provenance.

## Semantic comparison warning

The stacks use the closest available counterparts; they are not interchangeable
proof statements. Keep the profile, circuit variant, source commit, backend,
and `non_equivalence_note` together when interpreting results.

| Profile | Noir side | Circom side | Comparison boundary |
| --- | --- | --- | --- |
| Passport historical | Monolithic `complete_age_check` | Self registration plus `vc_and_disclose` | A staged product flow, not one monolithic statement |
| Passport P1 | [`noir/passport_p1/src/main.nr`](noir/passport_p1/src/main.nr) | [`circom/passport_p1/passport_p1.circom`](circom/passport_p1/passport_p1.circom) | Closest matched integrity, registry, DG1, and age assertion |
| OPRF O2 | World-ID-aligned Noir nullifier statement | World ID Protocol nullifier circuit | Same named profile and public nullifier; implementation details differ |
| WebAuthn | ES256 assertion binding challenge, type, origin, RP-ID, flags, and key | Pinned `privacy-ethereum/webauth-circom` analogue | Circom omits several Noir bindings |

TACEO's primitive OPRF example and other experimental candidates are retained
under [`legacy/`](legacy/README.md), not silently mixed into the publication
matrix.

## Reproduce

Inspect the complete non-secret plan first. This starts no devices and no paid
BrowserStack session:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all \
  --campaign provekit-v1-cross-device \
  --dry-run
```

The available stages are `bootstrap`, `prepare`, `smoke`, `measure`, `export`,
and `all`. A full run requires explicit paid-session confirmation:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all \
  --campaign provekit-v1-cross-device \
  --confirm-paid-browserstack
```

The Mac WASM lane is pinned to the fixed-16 policy automatically:

```text
INPUT_TO_PROOF_EXECUTION_POLICY=multithread
MOBENCH_WASM_THREADS=16
MOBENCH_SNARKJS_THREADS=16
```

Barretenberg requests 32 workers and records its 16-worker effective limit.
The runner refuses to export a successful series unless its proof and tamper
gates pass.

To validate retained evidence or regenerate the canonical CSV:

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
bun test benchmarks/v1/input-to-proof-data/native/*.test.ts
```

## Repository layout

```text
benchmarks/v1/
├── input-to-proof-data/       canonical CSV, exporter, schema, native helpers
├── noir/                      Noir circuits and browser fixtures
├── circom/                    Circom circuits and browser fixtures
├── barretenberg/              Barretenberg browser lane
├── rapidsnark/                Rapidsnark mobile crates, scaffold, and patches
├── wasm/                      ProveKit/SnarkJS browser harness and fixtures
├── mopro/                     Native Mopro adapter sources
├── scripts/                   Bootstrap, preparation, measurement, and shared tooling
└── legacy/                    superseded datasets, diagnostics, and historical docs
```

The `analysis/` directory is intentionally empty in this freeze for the
publication notebook. It must read only the canonical CSV, keep timing phases,
payload, proof-size, and memory separate, and render missing series visibly.

## Reproducibility and privacy rules

- Treat [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) and the two lock files as
  the campaign identity.
- Keep BrowserStack credentials in the caller's environment; never commit them.
- Keep raw device/session reports under the local `target/` evidence tree.
- Do not count APK/IPA upload size as proving payload.
- Do not use legacy CSVs, browser timings, estimates, or substituted cells in
  the canonical publication file.
