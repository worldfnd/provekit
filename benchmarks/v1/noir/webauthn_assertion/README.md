# Noir WebAuthn assertion fixture

This fixture is the canonical Noir WebAuthn counterpart. It binds the P-256
credential key, challenge, RP-ID hash, `webauthn.get` ceremony type, expected
origin, and required UP/UV flags. Registration, slot commitments, and
uniqueness are intentionally outside this isolated assertion profile.

The native campaign uses Noir beta.19 and Barretenberg rs 4.2.0-aztecnr-rc.2;
the ProveKit V1 browser lane uses its separately pinned beta.11 artifact. Keep
these frontends distinct in row provenance.

Generate the deterministic fixture and run the locked native preparation:

```bash
bun install --frozen-lockfile
bun run fixture
bash benchmarks/v1/scripts/build-provekit-webauthn.sh
```

The closest Circom counterpart is pinned in `sources.lock.json` and is not
statement-equivalent; the CSV retains that warning on every Circom row.
