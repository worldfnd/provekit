# Canonical native normalization helpers

This directory contains only the small helpers used by the canonical
input-to-proof export:

- `normalize-e15-provekit.ts` normalizes the retained ProveKit E15 reports;
- `normalize-e15-native-backend.ts` normalizes native Noir/Circom reports;
- `generate-e15-native-gaps.ts` emits the attested E15 gap rows;
- `export-benchmark-csv.ts` and `schema.ts` provide the shared row validator.

The old proof-only, semantic-parity, iOS-recovery, and Mac-browser normalizers
are under [`../../legacy/data/`](../../legacy/data/). They are retained for audit
history and are not inputs to `input-to-proof-samples.csv`.
