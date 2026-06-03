# V1 Passkey and WebAuthn Compatibility Log

Date: 2026-06-03

## Problem

The copied passkey and WebAuthn circuits use `noir-bignum` v0.9.2 and
`noir_bigcurve` v0.13.2 for explicit P-256 constraints. On the ProveKit v1
branch, `provekit-cli prepare` failed while type-checking dependency test code:

```text
No method named 'as_vector' found for type '[BLS12_381_Fq; 3]'
```

Using Noir's built-in `std::ecdsa_secp256r1::verify_signature` was not a valid
replacement on v1 because ProveKit v1's R1CS compiler does not lower
`BLACKBOX::ECDSA_SECP256R1`.

## Changes

- Added local compatibility copies:
  - `vendor/noir-bignum-v1` from `noir-bignum` v0.9.2
  - `vendor/noir-bigcurve-v1` from `noir_bigcurve` v0.13.2
- Pruned upstream CI, script, test, and benchmark directories from those local
  copies because they are not used by these examples.
- Updated `vendor/noir-bigcurve-v1/Nargo.toml` to depend on the local
  `vendor/noir-bignum-v1` path.
- Removed the upstream `mod tests;` and `mod benchmarks;` imports from the
  compatibility copies' `src/lib.nr` files. ProveKit v1 type-checks dependency
  test modules during preparation, and those upstream test modules use newer
  Noir APIs than v1 supports.
- Updated the passkey and WebAuthn example manifests to use the local
  compatibility copies instead of fetching those dependencies into the global
  Nargo cache.

The circuit logic was not changed. The examples still use the explicit
`noir_bigcurve`/`noir-bignum` P-256 verifier and still take `r_point_y` as the
private helper witness.

## Verification

Commands run from `/Users/dcbuilder/Code/provekit-v1-passkey-webauthn`:

```bash
target/release-fast/provekit-cli prepare noir-examples/passkey_p256 \
  --pkp noir-examples/passkey_p256/artifacts/prover.pkp \
  --pkv noir-examples/passkey_p256/artifacts/verifier.pkv \
  --skip-brillig-constraints-check
```

Result: exit code 0. R1CS: 195561 constraints, 353800 witnesses.

```bash
target/release-fast/provekit-cli prove \
  --prover noir-examples/passkey_p256/artifacts/prover.pkp \
  --input noir-examples/passkey_p256/Prover.toml \
  --out /tmp/provekit-v1-passkey.np
```

Result: exit code 0. `prove_with_toml`: about 1.00 s.

```bash
target/release-fast/provekit-cli verify \
  --verifier noir-examples/passkey_p256/artifacts/verifier.pkv \
  --proof /tmp/provekit-v1-passkey.np
```

Result: exit code 0. `verify`: about 44.9 ms.

```bash
target/release-fast/provekit-cli prepare playground/noir-webauthn-demo \
  --pkp playground/noir-webauthn-demo/artifacts/prover.pkp \
  --pkv playground/noir-webauthn-demo/artifacts/verifier.pkv \
  --skip-brillig-constraints-check
```

Result: exit code 0. R1CS: 388588 constraints, 644766 witnesses.

```bash
target/release-fast/provekit-cli prove \
  --prover playground/noir-webauthn-demo/artifacts/prover.pkp \
  --input playground/noir-webauthn-demo/Prover.toml \
  --out /tmp/provekit-v1-webauthn.np
```

Result: exit code 0. `prove_with_toml`: about 1.32 s.

```bash
target/release-fast/provekit-cli verify \
  --verifier playground/noir-webauthn-demo/artifacts/verifier.pkv \
  --proof /tmp/provekit-v1-webauthn.np
```

Result: exit code 0. `verify`: about 49.9 ms.
