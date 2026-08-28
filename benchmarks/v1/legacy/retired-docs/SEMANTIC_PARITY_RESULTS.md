# Historical ProveKit V1 semantic-parity results

This report is generated from
[`legacy/semantic-parity/semantic-parity-samples.csv`](legacy/semantic-parity/semantic-parity-samples.csv),
not from the older exploratory `legacy/data/benchmark-samples.csv`. The CSV contains
27 logical cells, one warmup and five measured samples per cell, and all four
publication metrics. ProveKit rows use core commit
`9b2a6f37c67691eab4b0cec6c35e35c520e93285` on every target.

The circuits are closest counterparts, not identical statements. Passport P1
is the monolithic matched age/integrity profile; WebAuthn is the pinned
privacy-ethereum closest analogue; OPRF O2 is the World ID nullifier profile.
The Circom and Noir rows retain their semantic notes in every CSV record.

This report is retained for historical comparison. It measures proving-only
rows and predates the canonical raw-input-to-proof rerun. Do not combine its
timings with the publication CSV.

## Median measured results

Times are prove-only milliseconds. Payload is the deduplicated bytes needed to
create a proof; proof is the serialized proof; RSS is peak process memory. The
CSV retains the five samples and hashes behind each median.

| Target | Workload | Stack | Prove ms | Payload bytes | Proof bytes | Peak RSS MiB |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Mac Chrome | Passport | ProveKit V1 | 10,216.280 | 2,313,739 | 963,449 | 998.125 |
| Mac Chrome | Passport | Noir + Barretenberg | 14,965.490 | 74,595,035 | 16,000 | 1,148.297 |
| Mac Chrome | Passport | Circom + Groth16 | 45,043.700 | 508,332,927 | 722 | 6,142.953 |
| Mac Chrome | WebAuthn | ProveKit V1 | 11,004.425 | 2,286,515 | 972,536 | 994.953 |
| Mac Chrome | WebAuthn | Noir + Barretenberg | 14,740.610 | 74,003,114 | 16,000 | 1,060.062 |
| Mac Chrome | WebAuthn | Circom + Groth16 | 219,079.600 | 1,753,618,376 | 724 | 11,064.781 |
| Mac Chrome | OPRF O2 | ProveKit V1 | 2,698.920 | 1,644,635 | 846,326 | 702.656 |
| Mac Chrome | OPRF O2 | Noir + Barretenberg | 6,199.425 | 73,925,206 | 16,000 | 909.375 |
| Mac Chrome | OPRF O2 | Circom + Groth16 | 1,631.400 | 39,203,507 | 724 | 3,096.328 |
| iPhone SE 2022 | Passport | ProveKit V1 | 2,384.364 | 2,554,715 | 715,102 | 535.313 |
| iPhone SE 2022 | Passport | Noir + Barretenberg | 4,109.934 | 20,480,588 | 16,324 | 506.672 |
| iPhone SE 2022 | Passport | Circom + Groth16 | 8,012.584 | 529,101,612 | 928 | 282.531 |
| iPhone SE 2022 | WebAuthn | ProveKit V1 | 3,182.688 | 2,410,560 | 714,756 | 565.250 |
| iPhone SE 2022 | WebAuthn | Noir + Barretenberg | 4,060.302 | 271,478,529 | 21,092 | 667.375 |
| iPhone SE 2022 | WebAuthn | Circom + Groth16 | 38,679.039 | 1,842,364,184 | 1,002 | 845.313 |
| iPhone SE 2022 | OPRF O2 | ProveKit V1 | 1,217.698 | 1,644,193 | 634,068 | 143.625 |
| iPhone SE 2022 | OPRF O2 | Noir + Barretenberg | 2,537.092 | 12,983,421 | 16,548 | 379.641 |
| iPhone SE 2022 | OPRF O2 | Circom + Groth16 | 586.212 | 40,639,660 | 1,602 | 103.906 |
| Motorola E15 | Passport | ProveKit V1 | 71,595.260 | 2,546,527 | 715,014 | 474.594 |
| Motorola E15 | Passport | Noir + Barretenberg | 115,303.106 | 20,480,588 | 16,324 | 463.227 |
| Motorola E15 | Passport | Circom + Groth16 | 53,063.891 | 529,101,612 | 1,035 | 649.945 |
| Motorola E15 | WebAuthn | ProveKit V1 | 27,839.158 | 2,377,056 | 716,454 | 498.574 |
| Motorola E15 | WebAuthn | Noir + Barretenberg | 107,456.725 | 271,478,529 | 21,092 | 483.887 |
| Motorola E15 | WebAuthn | Circom + Groth16 | 855,096.265 | 1,842,364,184 | 1,127 | 810.680 |
| Motorola E15 | OPRF O2 | ProveKit V1 | 12,564.926 | 1,644,193 | 632,628 | 177.336 |
| Motorola E15 | OPRF O2 | Noir + Barretenberg | 68,194.674 | 12,983,421 | 16,548 | 341.793 |
| Motorola E15 | OPRF O2 | Circom + Groth16 | 11,801.808 | 40,639,660 | 1,782 | 139.172 |

## Reading the comparison

- ProveKit V1 is the fastest of the three stacks for Passport on all targets,
  and for WebAuthn on all targets. Circom is fastest for OPRF O2 on all three
  targets in this table.
- ProveKit has the smallest proving payload in every workload/target row. Its
  WHIR proof is larger than Groth16 and Barretenberg proofs, so proof transport
  size is a separate trade-off from proving latency.
- Circom's Groth16 proof is tiny, but its WebAuthn payload and peak RSS are
  substantially larger. Barretenberg's proof is compact, but its CRS/SRS
  proving payload is much larger than ProveKit's PKP-plus-input payload.
- These are not a universal cryptographic ranking: the statement, frontend,
  proof system, and serialization differ. Use the workload notes and the
  sample-level provenance before making a product claim.

## Correctness and provenance

Every successful row came from a lane that accepted a valid proof and rejected
a tampered proof before timing. Mac browser memory is Chrome renderer RSS; it
is not JavaScript heap. Native memory is the benchmark process peak. Browser
ProveKit is the pinned single-thread V1 WASM build, not
`@worldcoin/provekit@0.1.0`; the npm package remains a compatibility reference
only.

Regenerate and validate the exact report with:

```bash
bun benchmarks/v1/semantic-parity-data/export-v1.ts
bun test benchmarks/v1/semantic-parity-data/export.test.ts
python3 -m unittest benchmarks/v1/analysis/test_benchmark_analysis.py
```
