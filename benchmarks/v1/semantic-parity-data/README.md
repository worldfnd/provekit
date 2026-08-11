# Historical semantic-parity campaign data

This directory contains the exporter, manifest, and evidence for the historical
proof-only semantic-parity sweep. It is not the publication source. The
resulting CSV is retained at
[`../legacy/semantic-parity/semantic-parity-samples.csv`](../legacy/semantic-parity/semantic-parity-samples.csv);
the canonical publication file is
[`../input-to-proof-data/input-to-proof-samples.csv`](../input-to-proof-data/input-to-proof-samples.csv).
The older exploratory export is at `../legacy/data/benchmark-samples.csv`.

`manifest.json` freezes the 27 expected profile × target × stack cells, the
semantic identities, exact Mac evidence hashes, and deduplicated proving
payload components. A payload includes everything required to create a proof
(circuit and frozen input plus PKP, zkey, or CRS as applicable), but excludes
verifier-only files, APK/IPA packages, and duplicate transport uploads.

Generate and validate the frozen campaign rows from the committed evidence:

```sh
bun benchmarks/v1/semantic-parity-data/export-v1.ts
bun test benchmarks/v1/semantic-parity-data/export.test.ts
```

The historical `../legacy/semantic-parity/semantic-parity-samples.csv`
contains exactly 162 rows across
all 27 cells: one warmup and five measured attempts per cell. All nine
ProveKit V1 cells are qualified from committed Mac, BrowserStack iPhone, and
physical E15 evidence. The exporter rejects missing V1 evidence, hash drift,
and incomplete sampling rather than silently falling back to current-main or
npm ProveKit timings.

The historical CSV deliberately uses the exact column order and units of
`../legacy/data/benchmark-samples.csv` so old notebooks can read it unchanged.
Internally validated `prove_time_ms`, `proving_payload_size_bytes`, and
`process_peak_memory_kib` are exported as legacy `prover_time_ms`,
`circuit_size_bytes`, and `peak_memory_mib` respectively. The semantic profile
is retained in `circuit_variant`, and its qualification note in
`non_equivalence_note`. This preserves the exact header and units of
`benchmark-samples.csv` while making the V1 source and evidence provenance
explicit.

## Native evidence handoff

Each native run must emit one JSON file matching `native-evidence.schema.json`.
The file represents exactly one cell and carries device/session provenance. It
is exactly one of:

- a successful series with artifact hashes, one warmup, five measured samples,
  both correctness gates, and all four headline metrics; or
- one structured `gap` with status `unsupported`, `build_failed`, `crashed`,
  `timed_out`, or `zero_samples`, a failure code/detail, and explicitly `null`
  metrics.

The warmup `prove_time_ms` may be `null` when Mobench attests it without
retaining its timing; measured times and all four headline metrics may never be
blank.

For future campaigns, native files can still be passed to the generic exporter
positionally and checked with the full matrix gate:

```sh
bun benchmarks/v1/semantic-parity-data/export.ts \
  target/v1-benchmarks/semantic-parity/passport-p1/iphone-native/provekit.json \
  target/v1-benchmarks/semantic-parity/oprf-o2/e15-native/provekit.json \
  --output=benchmarks/v1/legacy/semantic-parity/semantic-parity-samples.csv

bun benchmarks/v1/semantic-parity-data/export.ts target/.../*.json \
  --require-complete \
  --output=benchmarks/v1/legacy/semantic-parity/semantic-parity-samples.csv
```

The generic exporter prints separate `successful_cells` and `gap_cells` counts.
The V1 publication exporter prints `successful_cells: 27`; no gap or browser
substitution is accepted for the nine ProveKit V1 cells.

The exporter rejects evidence/artifact hash drift, duplicates, runtime/target
mixing, semantic-profile mismatches, missing correctness gates, incomplete 1+5
series, and blank/zero headline metrics. Unsupported cells must eventually be
represented as a single structured gap row; successful browser timings cannot
stand in for native evidence.

## WebAuthn closest analogue

The nine `webauthn_closest_analogue` cells are copied from the hash-locked
historical CSV because neither WebAuthn circuit changed. They are deliberately
not labeled semantically equivalent: Noir binds challenge, client-data type,
origin, RP-ID hash, UP/UV flags, and public key, while the
privacy-ethereum Circom circuit omits several of those bindings. Every row
retains the historical non-equivalence note, including the iPhone Circom
estimated-payload disclosure.

The exporter replaces stale historical `circuit_size_bytes` mappings with the
complete proving payload from frozen artifacts. ProveKit includes PKP/prover +
input, Barretenberg includes circuit + input/witness + consumed CRS/SRS, and
Circom includes WASM + zkey + input on Mac or zkey + frozen witness on native.
These are proving payloads; app packages and verifier-only files are excluded.
