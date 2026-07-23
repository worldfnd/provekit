# Noir / Barretenberg benchmark lane

Noir `1.0.0-beta.11` pins Barretenberg `0.87.0`. The native `bb` release and
`@aztec/bb.js` must use that same version so ProveKit and Barretenberg consume
the same beta.11 ACIR and fixture.

Install the browser dependency without changing the lock:

```bash
cd benchmarks/v1/barretenberg
bun install --frozen-lockfile
bun run smoke
```

The smoke runs the WebAuthn assertion circuit from `../noir/webauthn_assertion`
with the single-thread backend. Passport and OPRF are the next fixtures. Record the
Barretenberg CRS as part of the cold-download bundle. Do not publish
Barretenberg comparisons until a `0.87.0` proof and verification pass against
each frozen beta.11 artifact.

The package tarball integrity and release URL are pinned in
`../toolchains.lock.json`.
