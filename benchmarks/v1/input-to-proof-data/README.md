# Canonical input-to-proof data

[`input-to-proof-samples.csv`](input-to-proof-samples.csv) is the only
publication dataset in this branch. It has 41 stable columns and one row per
warmup or measured attempt. The current freeze is 417 rows across 72 logical
series: 345 measured, 69 warmups, and three explicit gap rows.

The headline field is `input_to_proof_time_ms`. It covers raw structured input,
fresh witness generation, and serialized proof generation. The companion
`witness_time_ms` and `prover_time_ms` fields are phase diagnostics where the
backend exposes them. ProveKit's native witness construction is integrated
with proving, so its witness phase is intentionally blank.

The four publication metrics are:

- `input_to_proof_time_ms` / `total_time_ms`;
- `proof_size_bytes` for the exact serialized proof;
- `circuit_size_bytes` for the deduplicated proving payload needed to create a
  proof (never APK/IPA upload size);
- `peak_memory_mib` for measured process RSS.

Gap rows have blank metrics and an explicit `status`, `failure_code`, and
`failure_detail`. They are not zeros, estimates, or values copied from another
target.

## Regeneration

The exporter consumes retained raw reports under `target/v1-benchmarks/` and
requires valid-proof acceptance plus tampered-proof rejection before timing is
accepted:

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
```

`merge-mac-fixed16.ts` is the idempotent provenance helper used to replace the
Mac portion with the fixed-16 campaign while retaining the mobile rows. Its
intermediate fixed-16 source CSV is preserved under `../legacy/wasm/`; it is
not a second publication dataset.

The native E15 normalizers and gap generator are in [`native/`](native/). The old
proof-only, semantic-parity, TACEO, and automatic-thread exporters are under
`../legacy/` and must not be used to update this file.
