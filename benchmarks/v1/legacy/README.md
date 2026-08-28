# Legacy benchmark material

The publication source is [`../input-to-proof-data/input-to-proof-samples.csv`](../input-to-proof-data/input-to-proof-samples.csv).
Everything in this directory is retained only for auditability and historical
comparison; it must not be merged into the canonical input-to-proof dataset.

## Retained history

- `data/benchmark-samples.csv` is the original exploratory export. It mixed
  proof-only timings, compound Passport registration/disclosure rows, and
  older circuit identities.
- `semantic-parity/semantic-parity-samples.csv` is the 27-cell proof-only
  rerun. Its timing begins after witness generation, so it is not an
  input-to-proof result.
- `semantic-parity-data/` contains the exporter and retained proof-only
  evidence for that rerun.
- `taceo-candidate/` contains an experimental Circom Helpers/Groth16 lane.
  It changed witness graphs, proving keys, and statements, so it is not a
  backend-only replacement for the canonical Circom rows.
- `wasm/` contains the superseded automatic-thread and fixed-16 Mac source
  exports used while rebuilding the canonical Mac rows. The fixed-16 result
  was merged into the canonical CSV; the source export remains here solely as
  provenance.
- `retired-docs/` contains the former semantic-parity, proof-only,
  multithreading, and command-transcript documents.
- `scripts/` contains superseded device runners, Android shard tooling,
  Barretenberg mobile packaging, and chart generators.
- `analysis/`, `data/`, `manifests/`, `examples/`, `arkworks-host/`, and
  `barretenberg-mobile/` contain diagnostic or superseded tooling not needed
  by the canonical reproduction entrypoint.

## Why the canonical campaign was rerun

1. Earlier headline rows measured proving only; the canonical boundary is raw
   structured input through serialized proof bytes, including witness
   generation.
2. Cold and warm initialization boundaries were inconsistent across stacks.
3. The old files mixed non-equivalent circuits and staged Passport product
   flows; the canonical file names four explicit profiles, including P1.
4. ProveKit is pinned to the V1 core commit and the Mac browser lane uses a
   fixed 16-worker build for ProveKit and SnarkJS.
5. Proof bytes, deduplicated proving payload, and peak process RSS are recorded
   separately; APK/IPA transport size is never used as proving payload.
6. Mobile rows require valid-proof acceptance, tampered-proof rejection, and
   one warmup plus five measured samples. The E15 Circom/WebAuthn OOM remains a
   blank structured gap rather than an estimate or a substituted value.

Historical files are intentionally not deleted. Their provenance is useful,
but their measurement contracts are different from the canonical campaign.
