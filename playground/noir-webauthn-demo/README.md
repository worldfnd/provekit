# noir_webauthn ProveKit Noir-backend demo

This isolated demo wraps `olehmisar/noir_webauthn` as a binary Noir package and
proves the library's WebAuthn/passkey signature verifier with ProveKit's Noir
compiler backend.

The fixture in `Prover.toml` is copied from the upstream `some_test` case in
`noir_webauthn` v0.37.2.

The upstream tag currently pins older transitive dependencies that do not
compile with this ProveKit Noir frontend. The upstream source also verifies
P-256 via Noir's built-in `std::ecdsa_secp256r1::verify_signature` black box,
which ProveKit does not lower yet.

This demo vendors `noir_webauthn` and keeps the WebAuthn challenge/hash flow,
while switching:

- `base64` to `noir-lang/noir_base64` `v0.5.0`
- `nodash` to a local SHA-256-only shim backed by `noir-lang/sha256` `v0.3.0`
- P-256 verification to `noir_bigcurve`/`noir-bignum`, with `r_point_y` supplied
  as a private helper witness

## Proof statement

The circuit asserts:

```text
webauthn::verify_signature(
  public_key_x,
  public_key_y,
  signature,
  client_data_json,
  authenticator_data,
  challenge,
  challenge_index,
  r_point_y,
) == true
```

Upstream `verify_signature` checks that the base64url challenge appears at the
given index inside `clientDataJSON`, computes the WebAuthn signed message
digest, and verifies the P-256 ECDSA signature. This demo preserves that shape,
but replaces the final ECDSA black box with explicit BigCurve constraints.

## Commands

```bash
../../target/release-fast/provekit-cli prepare . \
  --pkp artifacts/noir_webauthn_demo.pkp \
  --pkv artifacts/noir_webauthn_demo.pkv \
  --hash blake3 \
  --skip-brillig-constraints-check

../../target/release-fast/provekit-cli prove \
  --prover artifacts/noir_webauthn_demo.pkp \
  --input Prover.toml \
  --out artifacts/noir_webauthn_demo.np

../../target/release-fast/provekit-cli verify \
  --verifier artifacts/noir_webauthn_demo.pkv \
  --proof artifacts/noir_webauthn_demo.np
```

## Result

This adapted circuit prepares, proves, and verifies with ProveKit.

```text
ACIR: 176,936 witnesses, 48,581 opcodes
R1CS after optimization: 345,484 constraints, 558,078 witnesses
PKP: 2.3 MB
PKV: 4.1 MB
Proof: 3.0 MB
```

The generated artifacts are stored under `artifacts/`.

## Mavros note

This folder is not a Mavros proof. Mavros does not use ProveKit's ACIR-to-R1CS
lowering path. In ProveKit, `prepare --compiler mavros` expects a Mavros basic
artifacts JSON plus a Mavros-generated R1CS file:

```bash
../../target/release-fast/provekit-cli prepare basic_artifacts.json \
  --compiler mavros \
  --r1cs r1cs.bin \
  --pkp artifacts/prover.pkp \
  --pkv artifacts/verifier.pkv
```

The Mavros compiler/VM must produce those artifacts before ProveKit can package
and prove them.
