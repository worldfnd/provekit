# Legacy benchmark exports

These files are retained for auditability and historical comparison. They are
not the publication dataset. The canonical source is
[`../input-to-proof-data/input-to-proof-samples.csv`](../input-to-proof-data/input-to-proof-samples.csv).

## What each export contains

### `data/benchmark-samples.csv`

This was the original exploratory cross-device export. It mixed proof-only and
compound product variants, historical circuit identities, and earlier timing
boundaries. Circom Passport registration/disclosure and World ID OPRF
query/nullifier appear as separate variants, so its rows are useful for
debugging but are not one normalized input-to-proof matrix.

### `semantic-parity/semantic-parity-samples.csv`

This was the later proof-only rerun for 27 workload/target/stack cells. It
aligned the Passport P1 and OPRF O2 counterparts and corrected proof, payload,
and peak-RSS instrumentation. Its headline timing starts after witness
generation, and it preserves the earlier iPhone Circom payload estimate
disclosures. It is superseded by the input-to-proof campaign because witness
generation must be coupled to proving.

The historical exporter and evidence remain in
[`../semantic-parity-data/`](../semantic-parity-data/). Its default output is
the CSV in this directory:

```bash
bun benchmarks/v1/semantic-parity-data/export-v1.ts
bun test benchmarks/v1/semantic-parity-data/export.test.ts
```

### `taceo-candidate/`

This is an experimental fork using TACEO Circom Helpers/Groth16 production
material. It qualified some World ID OPRF production rows, but Passport,
Passport P1, and WebAuthn had witness-graph compatibility gaps. The candidate
also changes the optimized witness graph, zkey, and statement, so its apparent
speedup is not a backend-only apples-to-apples replacement for the frozen
Rapidsnark rows. Its CSV and evidence are preserved with the exporter and
configuration in that directory.

## Why the campaign was rerun

The final input-to-proof campaign was rerun rather than patched from the old
files for several concrete reasons:

1. Earlier headline numbers measured proving only and omitted witness
   generation; the new boundary is raw structured input through serialized
   proof bytes.
2. Cold and warm initialization boundaries were inconsistent across stacks.
3. The old exports mixed non-equivalent circuits and compound product flows;
   the new freeze names all four semantic profiles explicitly, including the
   additional Passport P1 pair.
4. ProveKit V1 had to be pinned to its branch/core commit and kept separate
   from current-main and the npm compatibility package.
5. Proof-size, proving-payload, and peak-process-memory instrumentation had to
   be corrected; APK/IPA upload size is transport evidence, not proving input.
6. The iPhone Circom OPRF lane needed the qualified `wasmi` witness path after
   the layout-sensitive Rust-Witness AOT artifact failed on iOS.
7. The E15 required explicit 32-bit ABI and address-space evidence. One cold
   Circom WebAuthn series remains a structured out-of-memory gap rather than
   an estimate or a substituted browser value.
8. Publication needed one immutable manifest, valid-proof/tamper gates, and
   exactly one warmup plus five sequential measured attempts per successful
   series.

The rerun therefore establishes a single reproducible measurement contract;
the legacy exports remain available to explain how earlier charts were made.
