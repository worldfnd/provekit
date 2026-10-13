# Joint witness opening

`WitnessOpeningMode::Joint` opens two existing witness commitments through `JointOpeningBackend`.
Separate mode remains the default.
Single-stage witnesses keep their existing opening path.

Select Joint mode before creating the transcript and call `scheme.validate_joint_backend(&backend)` before committing.
Use these entry points:

- `prove_noir_with_joint_backend`
- `prove_from_alphas_ctx_with_joint_backend`
- `verify_with_joint_backend`

The backend receives two ordered `N`-element commitments and forms over `[w1 | w2]`.
Claim order is A, B, C, optional public inputs, then optional stage challenges.
The backend binds both commitments and all values before sampling shared coefficients.
It returns one selector-first point and one coefficient per form.
ProveKit checks the result dimensions and completes `FinalClaim::verify`.
SPARK receives one combined matrix query.
The separate Spartan blinding opening follows the witness opening.

The serialized scheme binds the selected opening mode.
Affected binary formats use major version `3`.
Joint opening preserves the source commitment mode, including ZeroKnowledge.

The current WHIR pin lacks the pair API, so default entry points reject Joint mode.
The real adapter lives in `tooling/provekit-fixtures/tests/whir_pair.rs` until the dependency update.
ProveKit uses Arkworks 0.5; WHIR main uses 0.6.
The separate dependency migration must precede direct integration with WHIR main.
A compatibility checkout supports local acceptance tests without changing that pin.

```sh
cargo test --locked -p provekit-common joint_ --lib
cargo test --locked -p provekit-fixtures --test joint_opening
```

The tests cover readable arithmetic, ordered claims, public-input binding, and backend failures.
The real-backend fixture covers BN254, extension-field R1CS, and base-to-extension openings in both commitment modes.
Run it with a local compatibility checkout:

```sh
cargo --config 'patch."https://github.com/worldfnd/whir.git".whir.path="/path/to/whir-compat"' \
  rustc -p provekit-fixtures --test whir_pair -- --cfg whir_pair_backend
```

Run the emitted test executable and restore `Cargo.lock` after this local override.
