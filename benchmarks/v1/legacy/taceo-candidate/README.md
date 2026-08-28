# TACEO native Circom candidate CSV

This directory produces a publication-review fork of the frozen
`../../input-to-proof-data/input-to-proof-samples.csv`. It never changes that
canonical file.

Only these 16 logical series may be replaced:

- four semantic profiles: Passport historical, Passport P1, OPRF O2, WebAuthn;
- iPhone SE 2022 and Motorola E15 native targets;
- cold-local and warm-reuse timing modes;
- Circom/Groth16 only.

All ProveKit, Barretenberg, and Mac browser rows remain byte-for-byte equivalent
after CSV parsing. Export fails until all 16 evidence JSON files exist. A
successful series must contain exactly one real warmup followed by five measured
attempts. A genuine failure is represented by one explicit gap row with blank
metrics; it is never estimated and never filled from the Rapidsnark baseline.

The only currently qualified workload is the production World ID OPRF
query-plus-nullifier pair. It uses optimized witness graphs and matching Ark
zkeys, so it is labeled `O2-updated-production-query-plus-nullifier`; it is not
a backend-only replacement for the frozen Rapidsnark OPRF material. Passport,
Passport P1, and WebAuthn remain explicit compatibility gaps because
`circom-witness-rs` cannot generate their data-dependent witness graphs as
shipped.

## Evidence interface

Create `evidence/<series_id>.json` for every series printed by:

```sh
bun -e 'import { replacementSeries } from "./benchmarks/v1/legacy/taceo-candidate/export.ts"; console.log(replacementSeries.join("\n"))'
```

The JSON shape is exercised in `export.test.ts`. Identity pins live in
`config.json`. Artifact hashes must be lowercase SHA-256 values and cover at
least two proving inputs. `proving_payload_size_bytes` means every frozen file
needed to create a proof, deduplicated; it is not an IPA/APK upload size.
Measured attempts require process peak RSS. Every series must pass valid-proof
acceptance and tampered-proof rejection. Separate witness/prover timings may be
blank only when the native runner instruments the coupled input-to-proof span;
the coupled timing must always be present.

Run:

```sh
bun test benchmarks/v1/legacy/taceo-candidate/export.test.ts
bun benchmarks/v1/legacy/taceo-candidate/export.ts
```

The output is `input-to-proof-samples.taceo-candidate.csv` in this directory.
Use environment variables `TACEO_BASELINE_CSV`, `TACEO_EVIDENCE_DIR`, and
`TACEO_CANDIDATE_CSV` to override paths in automation.

## 2026-08-11 result

Measured medians exclude the warmup row:

| Target | Mode | Frozen Rapidsnark | TACEO updated production | Relative time | TACEO peak RSS |
|---|---:|---:|---:|---:|---:|
| iPhone SE 2022 | cold | 5,147 ms | 4,797 ms | 1.07x faster | 204.59 MiB |
| iPhone SE 2022 | warm | 5,168 ms | 492 ms | 10.50x faster | 184.66 MiB |
| Motorola E15 | cold | 75,244 ms | 11,921 ms | 6.31x faster | 245.68 MiB |
| Motorola E15 | warm | 75,200 ms | 7,280 ms | 10.33x faster | 234.95 MiB |

These ratios are useful production-path evidence but are not backend-only
speedups. The TACEO rows use shorter optimized witness graphs and matching Ark
zkeys. The iPhone warm row additionally measures cached nullifier generation
after query setup, while its cold row measures query plus nullifier. Proof size
is 256 bytes for paired query-plus-nullifier rows and 128 bytes for the cached
nullifier row; the frozen Rapidsnark rows serialize Groth16 proof JSON at about
1,602 bytes and are not byte-format comparable.

The candidate has 72 logical series and 372 rows: 60 complete 1+5 series and
12 explicit TACEO compatibility gaps. It should not replace the canonical CSV
for a general three-backend blog comparison. It can support a separately
labeled production OPRF section that discloses the material and warm-boundary
differences.
