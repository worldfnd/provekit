# Joint witness opening

Select `prepare --joint-opening`, or set `WitnessOpeningMode::Joint` before creating the transcript.
Separate opening remains the default. Single-stage witnesses use their existing opening path.

The normal prover and verifier call WHIR `prove_pair` and `verify_pair` directly.
Both commitments keep their original encoding and order.
Forms describe the padded witness `[w1 | w2]`.
A, B, and C remain separate claims; each adds its two witness-stage contributions.
Public inputs bind the first block. Stage challenges bind the second block.
WHIR binds the claim values before sampling shared coefficients.
The verifier completes `FinalClaim::verify`.
SPARK receives one query with the witness selector first.
The separate Spartan blinding opening follows the witness opening.

Standard and ZeroKnowledge commitment modes both support joint opening.
The serialized scheme binds the opening mode. Affected binary formats use major version `3`.
Build against the matching WHIR joint-opening branch.

```sh
cargo test --locked -p provekit-common joint_ --lib
cargo test --locked -p provekit-fixtures --test joint_opening
```

Tests use the normal APIs without a custom backend or build configuration.
They cover BN254, extension-field witnesses, genuine base-to-extension openings, and claim binding.
