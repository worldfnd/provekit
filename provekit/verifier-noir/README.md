# ProveKit Noir Recursive Verifier

This directory contains the Noir recursive verifier circuit for ProveKit WHIR+Spartan proofs.

## Is This Setup Simple?

Short answer: **moderate complexity**.

- **Simple part:** running the CLI pipeline (`prepare -> prove -> generate-noir-inputs`).
- **Tricky part:** keeping `src/types.nr` constants exactly aligned with the proof's WHIR config.
- **Hardest part (current gap):** automatically extracting all Merkle proof arrays from proof hints into Noir `Prover.toml`.

## End-to-End Verification Procedure

Use this flow to verify an inner Noir circuit proof with `verifier-noir`.

### 0) Build ProveKit CLI (once)

From repo root:

```bash
cargo build -p provekit-cli --release
```

### 1) Compile the inner circuit

```bash
cd <inner-circuit-dir>
nargo compile
```

This produces `target/<package>.json`.

### 2) Prepare ProveKit artifacts (IMPORTANT: use SHA256)

From repo root:

```bash
./target/release/provekit-cli prepare <path/to/target/program.json> \
  --hash sha256 \
  --pkp /tmp/noir-verifier-test/verifier.pkp \
  --pkv /tmp/noir-verifier-test/verifier.pkv
```

### 3) Produce a proof

```bash
./target/release/provekit-cli prove \
  /tmp/noir-verifier-test/verifier.pkp \
  <path/to/inner-circuit/Prover.toml> \
  --out /tmp/noir-verifier-test/proof.np
```

### 4) Generate Noir verifier inputs + config

```bash
./target/release/provekit-cli generate-noir-inputs \
  /tmp/noir-verifier-test/verifier.pkv \
  /tmp/noir-verifier-test/proof.np \
  --output /tmp/noir-verifier-test/Prover.toml \
  --json /tmp/noir-verifier-test/noir_verifier_data.json
```

This command also runs Rust-side verification as a sanity check.

### 5) Update verifier constants (`src/types.nr`)

Read `/tmp/noir-verifier-test/noir_verifier_data.json` and update the corresponding constants in:

- `src/types.nr`

At minimum, keep these in sync:

- `LOG_NUM_CONSTRAINTS`, `LOG_NUM_VARIABLES`
- `NUM_WHIR_ROUNDS`, `FOLDING_FACTOR`
- `MAX_QUERIES_PER_ROUND`, `TREE_HEIGHT`, `OOD_SAMPLES`
- `NUM_WITNESS_VARIABLES`, `NUM_W_FOLDED_EVALS`, `MAX_GAMMAS`
- `FINAL_POLY_SIZE`, `FINAL_SUMCHECK_ROUNDS`
- all `BLINDING_*` constants (including final-round sizes)

### 6) Copy generated prover input into this directory

```bash
cp /tmp/noir-verifier-test/Prover.toml ./Prover.toml
```

### 7) Compile and run verifier circuit

```bash
nargo check
nargo execute --force
```

If execution succeeds, the recursive verifier accepted the proof.

## Important Notes

1. `verifier-noir` is a **fixed-shape circuit**. Any change in inner proof config can require a `types.nr` update + recompilation.
2. Hash config must match end-to-end. This verifier expects SHA256 transcript behavior.
3. Current automation status:
   - Core transcript/prover-message parsing is implemented in `generate-noir-inputs`.
   - Merkle proof arrays from hints may still require additional extraction work depending on test case/config.

## Quick Troubleshooting

- **`nargo check` fails with size mismatches:** constants in `src/types.nr` are out of sync with JSON.
- **Transcript/assert mismatch during execute:** input data and constants are from different proof/circuit runs.
- **Very slow compile/execute:** expected for larger configs (large `MAX_GAMMAS`, large `LOG_NUM_VARIABLES`).
