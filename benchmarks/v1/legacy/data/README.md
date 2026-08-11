# Historical exploratory benchmark sample data

`benchmark-samples.csv` is retained as the original exploratory/compound
variant export. It is not canonical; use
[`../../input-to-proof-data/input-to-proof-samples.csv`](../../input-to-proof-data/input-to-proof-samples.csv)
for publication. Generate this historical format from normalized JSON attempt
records:

```sh
bun benchmarks/v1/data/export-benchmark-csv.ts \
  path/to/attempts.json \
  benchmarks/v1/legacy/data/benchmark-samples.csv
```

The default validation gate requires all 27 hardware × circuit × prover cells.
A successful variant contains sample indexes `0..5`: one `warmup` and five
`measured` attempts. An unavailable variant contains exactly one `gap` attempt
whose status explains why it has no samples. Gap metrics must be JSON `null` and
are exported as blank CSV fields; zero is always a measurement.

Mobench attests that native warmups ran but intentionally does not retain their
durations. Native warmup rows therefore use `status=ok` with blank timing
fields. The five measured rows always contain real durations; no warmup
duration is inferred or copied.

Use `--allow-partial` only while collecting data. It relaxes matrix coverage and
sample-count checks, but retains record-level, duplicate, unit, status, runtime,
and gap validation.

Times are milliseconds, memory is MiB, and proof size is bytes. Circom witness
time is separate from Groth16 prover time. `total_time_ms` may include boundary
overhead but cannot be smaller than witness plus prover time.
Every successful measured row must include the campaign's four headline
metrics: `prover_time_ms`, deduplicated proving payload in
`circuit_size_bytes` (mirrored in `artifact_size_bytes` and
`bundle_size_bytes` for compatibility), `proof_size_bytes`, and process peak
RSS in `peak_memory_mib`.

This export has 27 base cells and 33 historical variant series. Five iPhone
Circom variants predate structured payload telemetry; their payload is a
labelled asset-size estimate of the pinned zkey plus frozen WTNS witness. The
estimate is recorded in `non_equivalence_note` and excludes IPA and transport
sizes. Do not generalize that exception to other rows.

The three target surfaces are fixed:

- `iphone_se_2022` → `ios_native`
- `motorola_e15` → `android_native`
- `macbook_m4` → `browser_wasm`

Circuit counterparts are explicitly not statement-equivalent. Every record
therefore requires a reader-facing `non_equivalence_note`; charts must not imply
an apples-to-apples cryptographic comparison. `circuit_variant` keeps compound
counterparts separate within a base comparison cell, including Self passport
registration/disclosure and World ID Protocol OPRF query/nullifier. Every
successful variant independently requires one warmup and five measured samples.
