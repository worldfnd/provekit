# ProveKit V1 input-to-proof benchmarks

This directory contains the reproducible publication campaign for the
canonical file [`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv).
The headline measurement starts at raw structured inputs and ends after the
serialized proof is produced. Witness generation and proving are coupled;
verification and tamper rejection are correctness gates outside the headline.

The current freeze contains 417 sample rows across 72 logical series:

- 4 workload profiles × 3 stacks × 3 targets × 2 timing modes;
- 345 measured samples and 69 attested warmups;
- 3 explicit gaps: fixed-16 Mac Circom/WebAuthn cold and warm, plus E15
  Circom/WebAuthn cold. Gap metrics are blank, never zero or substituted.

## Matrix

| Stack | iPhone SE 2022 | Motorola E15 | M4 Max MacBook |
| --- | --- | --- | --- |
| ProveKit V1 | native Mobench / WHIR | native Mobench / WHIR | Chrome WASM, fixed 16 workers |
| Noir + Barretenberg | Mopro native | Mopro native where qualified | Chrome WASM, 16 effective workers |
| Circom + Groth16 | Mopro native / Rapidsnark | Mopro native; target-specific fallback evidence | Chrome WASM / SnarkJS, 16 workers |

Targets are separate runtime categories. The Mac publication surface is
Chrome/WASM; Mac-native runs are diagnostic only. BrowserStack credentials and
paid-session confirmation stay outside the repository.

## Workload identities

These are closest practical counterparts, not statement-equivalent circuits.
The CSV keeps the profile, circuit variant, source commit, backend, and
non-equivalence note on every row.

- **Passport historical:** Noir monolithic `complete_age_check` versus Self's
  registration plus `vc_and_disclose` product flow.
- **Passport P1:** the matched monolithic pair in
  [`noir/passport_p1/src/main.nr`](noir/passport_p1/src/main.nr) and
  [`circom/passport_p1/passport_p1.circom`](circom/passport_p1/passport_p1.circom).
- **OPRF O2:** the World-ID-aligned Noir nullifier statement versus the World
  ID Protocol Circom nullifier circuit. TACEO's primitive example is retained
  only under [`legacy/`](legacy/README.md).
- **WebAuthn:** Noir's ES256 assertion bindings versus the pinned
  `privacy-ethereum/webauth-circom` closest counterpart, which omits some
  bindings.

## Reproduce

The canonical guide is [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md). It records
the immutable source and toolchain locks, circuit/artifact hashes, device
identity, build prerequisites, sampling contract, and unsupported cells.

Inspect the complete non-secret plan first:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all --campaign provekit-v1-cross-device --dry-run
```

The supported stages are `bootstrap`, `prepare`, `smoke`, `measure`, `export`,
and `all`. A normal Mac preparation/measurement uses the canonical fixed-16
policy automatically:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all --campaign provekit-v1-cross-device \
  --confirm-paid-browserstack
```

The runner sets `INPUT_TO_PROOF_EXECUTION_POLICY=multithread`,
`MOBENCH_WASM_THREADS=16`, and `MOBENCH_SNARKJS_THREADS=16` for the Mac WASM
lane. Barretenberg requests 32 workers and reports its 16-worker effective
limit. Each successful series performs one warmup followed by five sequential
measured samples, and refuses to export before valid-proof and tampered-proof
checks pass.

To validate or regenerate the committed CSV from retained raw evidence:

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
```

The `analysis/` directory is intentionally empty in this freeze. Remco will
add the publication Marimo notebook there; it must read only the canonical CSV
and keep coverage, latency, witness/prover phases, payload, proof-size, and
memory figures separate while rendering missing series as gaps.

## Layout policy

The root contains only the canonical guide, locks, source/build inputs, the
canonical data/export path, and the scripts required to reproduce it. Superseded
CSVs, proof-only and semantic-parity runs, TACEO candidates, old notebooks,
diagnostic adapters, command transcripts, and automatic-thread exports are
preserved under [`legacy/`](legacy/README.md).

Backend-specific sources live under their backend directory. Rapidsnark's
mobile crates, iOS scaffold, and iOS patches are grouped under
[`rapidsnark/`](rapidsnark/); the shared browser RSS sampler lives with the
reproduction scripts. The native Mopro adapter sources remain under
[`mopro/`](mopro/), while E15 normalization helpers remain separate from the
committed publication CSV under [`data/`](data/).
