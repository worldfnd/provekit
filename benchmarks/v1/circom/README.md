# Circom native benchmark lanes

There are two distinct native Groth16 implementations:

- Rapidsnark consumes a Circom witness (`.wtns`) and the original `.zkey`.
- Arkworks uses `circom-witness-rs` for a mobile-safe native witness graph and
  Arkworks Groth16 proving material.

`circom-compat` is pinned as the desktop preparation/reference implementation.
It must not be pulled into the iOS runtime unchanged: its witness path includes
Wasmer. Mobile uses the graph interpreter from `circom-witness-rs` instead.

## First runnable workload: World ID OPRF

The pinned World ID Protocol source already contains:

- deterministic query/nullifier fixtures;
- serialized witness graphs;
- Arkworks proving keys; and
- a Mobench crate at `crates/zk-mobile-bench`.

Verify the checked-in source artifacts before building:

```bash
benchmarks/v1/scripts/verify-circom-artifacts.sh
```

Compile the pinned mobile crate and generate one real Arkworks Groth16 query
proof with:

```bash
benchmarks/v1/scripts/smoke-arkworks-oprf.sh
```

The first Arkworks mobile run should reuse the source crate's query functions:

- `bench_query_witness_generation_only`;
- `bench_query_proving_only`;
- `bench_query_cached_proof_generation`; and
- the matching nullifier functions.

These are World ID application circuits. They are not semantically equivalent
to the smaller `oprf-nr/oprf_example` Noir circuit and must be reported as a
separate workload.

## Passport

Self's passport flow is a two-proof product flow:

1. a signature-specific registration circuit; and
2. `vc_and_disclose`, which applies disclosure and age predicates.

That is not equivalent to ProveKit's monolithic `complete_age_check`. Report
both Self stages separately until a matching Circom statement exists. Never
present either stage alone as a direct passport comparison.

## Passkey

No licensed Circom circuit was found that matches the benchmark's ES256
assertion statement (challenge, RP ID hash, ceremony type, origin, flags, and
credential key). This lane remains a new-circuit task and an equivalence gate.

## Rapidsnark mobile

The pinned Rapidsnark source supports Android NDK and iOS static-library
builds. The adapter must expose witness, prove, and verify phases separately
through Mobench. Before distributing an iOS app, document the LGPL relinking
strategy for the statically linked library.

The host prover bootstrap is:

```bash
benchmarks/v1/scripts/build-rapidsnark-host.sh
```
