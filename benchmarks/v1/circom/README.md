# Circom + Groth16 lane

The canonical Circom backend is Groth16 with SnarkJS in Chrome and the pinned
Mopro-native Rapidsnark adapter on supported mobile targets. The preferred
native witness path is `witnesscalc-adapter@0.1.7`; the exact circuit, witness,
zkey, and backend are recorded per CSV row. The iPhone OPRF lane uses the
qualified Wasmi witness runtime because its native AOT witness artifact was
layout-unsafe on iOS.

The Motorola E15 is a confirmed 32-bit `armeabi-v7a` userspace. Its rows retain
the target-specific backend evidence. The Circom WebAuthn cold series remains
an explicit out-of-memory gap because the device cannot map the pinned zkey
and WTNS; no other target's value is substituted.

Verify frozen Circom artifacts and run the local browser smoke:

```bash
bash benchmarks/v1/scripts/verify-circom-artifacts.sh
cd benchmarks/v1/circom/web
bun install --frozen-lockfile
bun run build
bun run smoke
```

The browser campaign sets SnarkJS to exactly 16 requested/effective workers.
Self Passport registration/disclosure and World ID query/nullifier circuits are
reported as their named counterparts, not as equivalent Noir statements.
