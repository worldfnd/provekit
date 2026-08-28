# Noir + Barretenberg lane

This is the canonical Noir/Barretenberg implementation used by the
input-to-proof campaign. Native mobile integration is through Mopro 0.3.7;
the Mac publication surface uses `noir_js@1.0.0-beta.19` with
`@aztec/bb.js@4.2.0-aztecnr-rc.2`.

Install the locked browser dependencies and build the fixture bundle:

```bash
cd benchmarks/v1/barretenberg
bun install --frozen-lockfile
bun run build:web
bun run smoke:web
```

The smoke must generate a valid proof, verify it, and reject a tampered proof
for every selected workload before timing. Browser runs use the canonical
fixed-16 policy: Barretenberg requests 32 workers and records 16 effective
workers. Native reports retain their actual Mopro/Barretenberg backend and
device identity.

The source and SRS/package integrity pins are in
[`../toolchains.lock.json`](../toolchains.lock.json). Generated `dist/` and
runtime caches are ignored; only raw evidence and the canonical CSV are
publication data.
