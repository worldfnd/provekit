# Two-witness opening status

The Standard two-witness path is implemented through `JointOpeningBackend`.
The matching WHIR branch implements the protocol.
ZeroKnowledge remains incomplete and fails before commitment or opening transcript changes.
The existing single-witness WHIR ZeroKnowledge path still exposes private witness information.

## Branches and stages

The existing `zkfr/combined-opening-witness` branch remains unchanged.
This branch, `zkfr/two-witness-opening`, starts from ProveKit `main` at `35324c0d`.
Its first three commits contain these stages:

1. Selector forms and combined claims: `9f69ad9b`.
2. Backend contract, validation, and format changes: `53ee17f7`.
3. Prover and verifier integration with readable routing tests: `58003f57`.

WHIR has a separate `zkfr/two-witness-opening` branch based on its `main` at `afec1fac`.
Its stages cover parameter derivation, paired execution, the zero-witness repair, and privacy documentation.
The WHIR checkout contains `docs/two-witness-opening.md` with exact protocol details.

## ProveKit interface

Select `WitnessOpeningMode::Joint` before creating the transcript.
Call `scheme.validate_joint_backend(&backend)` before committing witnesses.
Use these injected entry points:

- `prove_noir_with_joint_backend`
- `prove_from_alphas_ctx_with_joint_backend`
- `verify_with_joint_backend`

The default entry points use `UnavailableJointOpening` for Joint mode.
Separate mode remains the constructor default.
A Standard single-stage witness retains the existing opening path.
The serialized scheme requires an explicit opening mode.
All affected binary formats now use major version `3`.

`JointOpeningBackend` receives two ordered existing commitment handles.
The source configuration describes each padded `N`-element witness.
Forms describe the virtual `2N`-element witness `[w1 | w2]`.
Claim order is A, B, C, optional public inputs, then optional stage challenges.
ProveKit binds these values before the backend samples shared claim coefficients.
WHIR also binds the values at its public API boundary.
This duplicates at most five field elements and prevents caller-dependent claim binding.

The backend returns one selector-first point with `log2(N) + 1` coordinates.
It also returns one coefficient per supplied form.
ProveKit validates these dimensions and calls `FinalClaim::verify`.
SPARK receives one combined matrix query with the complete point.
The separate Spartan blinding opening follows the paired witness opening.

## Tests

```sh
cargo test --locked -p provekit-common joint_ --lib
cargo test --locked -p provekit-fixtures --test joint_opening
```

The algebra tests include `20 + 146 = 166` and `3 * 4 = 12`.
The routing tests use a recording backend and do not establish cryptographic correctness.
They check commitment count, claim order, binding checks, complete points, and backend errors.
A transcript-control test checks that Joint ZeroKnowledge rejection occurs before commitment messages.

`tooling/provekit-fixtures/tests/whir_pair.rs` contains acceptance tests for the real WHIR backend.
Its explicit `whir_pair_backend` configuration requires the WHIR compatibility branch.
The normal dependency pin lacks the new API, so default builds skip this fixture.

From a clean checkout, substitute the compatibility checkout path in this command:

```sh
RUSTFLAGS='--cfg whir_pair_backend' cargo \
  --config 'patch."https://github.com/worldfnd/whir.git".whir.path="/path/to/whir-compat"' \
  test -p provekit-fixtures --test whir_pair
```

The override changes `Cargo.lock`; keep that local change outside the implementation commits.
The fixture proves full BN254 and extension-leaf Goldilocks R1CS instances.
It also opens base-field witnesses with genuine extension coefficients through the same adapter.
It checks public-input binding, stage challenges, complete SPARK points, and malformed proofs.

## Remaining work

WHIR `main` uses Arkworks 0.6, while ProveKit currently uses the 0.5 WHIR revision `78e9460`.
The WHIR compatibility branch carries the same implementation for current ProveKit integration tests.
[ProveKit PR #507](https://github.com/worldfnd/provekit/pull/507) already contains the Arkworks 0.6 upgrade.
That dependency update must precede direct use of the WHIR main-based branch.
The production backend then needs the small adapter currently exercised by the fixture.

Base-committed Goldilocks cannot currently store an extension challenge in one base-field witness slot.
Full challenge-bearing R1CS tests therefore use `GoldilocksEfField`.
The WHIR paired protocol itself supports `Basefield<Field64_3>` with genuine extension coefficients.

A valid inherited WHIR ZeroKnowledge proof discloses an unclaimed coordinate through mask reconciliation.
The WHIR audit recovers `123456789` from a proof whose public claim equals zero.
Removing only the reconciliation scalar does not repair the later mask disclosures.
An efficient repair needs aggregate mask obligations, a terminal opening, and new security accounting.
A full-vector alternative needs uniform target-field blinders and separate soundness accounting.
Neither privacy repair is implemented in this branch.
