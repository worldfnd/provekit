# ProveKit Noir Recursive Verifier

This directory contains the Noir recursive verifier circuit for ProveKit WHIR+Spartan proofs.

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

### 4) Generate Noir verifier inputs + config (auto-sync mode)

```bash
./target/release/provekit-cli generate-noir-inputs \
  /tmp/noir-verifier-test/verifier.pkv \
  /tmp/noir-verifier-test/proof.np
```

By default, this command now:

- writes `provekit/verifier-noir/Prover.toml`
- writes `provekit/verifier-noir/noir_verifier_data.json`
- updates `provekit/verifier-noir/src/types.nr`
- fills all Merkle opening arrays from proof hints (round/final + blinding variants)

Optional overrides:

```bash
./target/release/provekit-cli generate-noir-inputs \
  /tmp/noir-verifier-test/verifier.pkv \
  /tmp/noir-verifier-test/proof.np \
  --output <path/to/Prover.toml> \
  --json <path/to/noir_verifier_data.json> \
  --types <path/to/types.nr>
```

This command also runs Rust-side verification as a sanity check.

### 5) (If needed) manually inspect or adjust constants

`generate-noir-inputs` auto-syncs `src/types.nr`, so manual edits are usually unnecessary.
Use this section only when auditing or overriding.

## How To Sync `types.nr` (Mechanical Mapping)

Use values from the generated JSON (`--json /tmp/.../noir_verifier_data.json`) and map as follows:

- `LOG_NUM_CONSTRAINTS` <- `LOG_NUM_CONSTRAINTS`
- `LOG_NUM_VARIABLES` <- `LOG_NUM_VARIABLES`
- `NUM_WHIR_ROUNDS` <- `NUM_WHIR_ROUNDS`
- `FOLDING_FACTOR` <- `FOLDING_FACTOR`
- `MAX_QUERIES_PER_ROUND` <- `MAX_QUERIES_PER_ROUND`
- `TREE_HEIGHT` <- `TREE_HEIGHT`
- `OOD_SAMPLES` <- `OOD_SAMPLES`
- `MAX_PUBLIC_INPUTS` <- `MAX_PUBLIC_INPUTS`
- `NUM_CHALLENGES` <- `NUM_CHALLENGES`
- `W1_SIZE` <- `W1_SIZE`
- `BATCH_SIZE` <- `BATCH_SIZE`
- `NUM_WITNESS_VARIABLES` <- `NUM_WITNESS_VARIABLES`
- `NUM_LINEAR_FORMS` <- `NUM_LINEAR_FORMS`
- `NUM_W_FOLDED_EVALS` <- `NUM_W_FOLDED_EVALS`
- `FINAL_POLY_SIZE` <- `FINAL_POLY_SIZE`
- `FINAL_SUMCHECK_ROUNDS` <- `FINAL_SUMCHECK_ROUNDS`
- `BLINDING_OOD_SAMPLES` <- `BLINDING_OOD_SAMPLES`
- `BLINDING_WHIR_ROUNDS` <- `BLINDING_WHIR_ROUNDS`
- `BLINDING_TREE_HEIGHT` <- `BLINDING_TREE_HEIGHT`
- `BLINDING_MAX_QUERIES` <- `BLINDING_MAX_QUERIES`
- `NUM_BLINDING_VECTORS` <- `BLINDING_NUM_VECTORS`
- `BLINDING_FINAL_POLY_SIZE` <- `BLINDING_FINAL_POLY_SIZE`
- `BLINDING_FINAL_SUMCHECK_ROUNDS` <- `BLINDING_FINAL_SUMCHECK_ROUNDS`
- `MAX_GAMMAS` <- `NUM_GAMMAS`

Derived constants to recompute/check:

- `FOLD_SIZE = 1 << FOLDING_FACTOR`
- `INTERLEAVING_DEPTH = FOLD_SIZE` (single vector mode)
- `STIR_BYTES_PER_INDEX = (TREE_HEIGHT + 7) / 8`
- `BLINDING_STIR_BYTES_PER_INDEX = (BLINDING_TREE_HEIGHT + 7) / 8`
- `STIR_TOTAL_BYTES = MAX_QUERIES_PER_ROUND * STIR_BYTES_PER_INDEX`
- `BLINDING_STIR_TOTAL_BYTES = BLINDING_MAX_QUERIES * BLINDING_STIR_BYTES_PER_INDEX`
- `EQ_ROW_SIZE = 1 << LOG_NUM_CONSTRAINTS`
- `EQ_COL_SIZE = 1 << LOG_NUM_VARIABLES`

## `basic-2` Example (Actual Output)

For `noir-examples/basic-2`, generated config was:

- `LOG_NUM_CONSTRAINTS=1`
- `LOG_NUM_VARIABLES=13`
- `NUM_WHIR_ROUNDS=3`
- `FOLDING_FACTOR=3`
- `MAX_QUERIES_PER_ROUND=127`
- `TREE_HEIGHT=12`
- `OOD_SAMPLES=1`
- `MAX_PUBLIC_INPUTS=0`
- `NUM_WITNESS_VARIABLES=13`
- `NUM_W_FOLDED_EVALS=56`
- `FINAL_POLY_SIZE=2`
- `FINAL_SUMCHECK_ROUNDS=1`
- `BLINDING_WHIR_ROUNDS=3`
- `BLINDING_TREE_HEIGHT=11`
- `BLINDING_FINAL_POLY_SIZE=1`
- `BLINDING_FINAL_SUMCHECK_ROUNDS=0`
- `NUM_GAMMAS=1016`

Important: even though `basic-2` is a tiny inner circuit, WHIR currently pads/sets witness-domain parameters so `LOG_NUM_VARIABLES` is still `13` in this proof configuration.

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
   - Merkle openings are extracted from hints in protocol order and wired into all circuit Merkle inputs.
   - Generation fails fast on inconsistent/missing hint sections instead of silently zero-filling.

## Quick Troubleshooting

- **`nargo check` fails with size mismatches:** constants in `src/types.nr` are out of sync with JSON.
- **Transcript/assert mismatch during execute:** input data and constants are from different proof/circuit runs.
- **Very slow compile/execute:** expected for larger configs (large `MAX_GAMMAS`, large `LOG_NUM_VARIABLES`).
