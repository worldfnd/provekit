# WebAuthn assertion benchmark

This circuit isolates one ES256 assertion from the World ID passkey ownership
flow. It deliberately excludes registration, slot commitments, registry
membership, and uniqueness.

The statement binds:

- the P-256 credential public key;
- the challenge embedded in `clientDataJSON`;
- the RP ID hash in `authenticatorData`;
- the `webauthn.get` ceremony type;
- the expected origin; and
- required authenticator flags (the fixture requires user presence and user
  verification).

The P-256 implementation is the `webauthn` library vendored by the pinned
World ID Protocol source. It currently relies on a `noir_bigcurve` vendor tree
whose redistribution license needs clarification. The benchmark therefore
references the pinned checkout under `target/` instead of copying that tree
into ProveKit.

Generate the deterministic fixture:

```bash
bun install --frozen-lockfile
bun run fixture
```

This writes matching `Prover.toml` and browser-ready `inputs.json` files.

Compile with the V1-compatible Noir frontend:

```bash
nargo compile --force --skip-brillig-constraints-check
```

Use Noir `1.0.0-beta.11`. Newer Noir versions are not API-compatible with the
pinned WebAuthn dependencies.

To compile, prepare, prove, verify, and hash the complete native artifact set:

```bash
benchmarks/v1/scripts/build-provekit-webauthn.sh
```
