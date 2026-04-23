# ProveKit Noir Recursive Verifier (Poseidon2)

This directory contains the Noir recursive verifier circuit for ProveKit WHIR+Spartan proofs
generated with `HashConfig::Poseidon2`.

## End-to-End Verification Procedure

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

Produces `target/<package>.json`.

### 2) Prepare ProveKit artifacts (Poseidon2 hash config)

From repo root:

```bash
./target/release/provekit-cli prepare <path/to/target/program.json> \
  --hash poseidon2 \
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
  /tmp/noir-verifier-test/proof.np
```

By default, this command:

- writes `provekit/verifier-noir/Prover.toml`
- writes `provekit/verifier-noir/noir_verifier_data.json`
- updates `provekit/verifier-noir/src/types.nr`
- fills all Merkle opening arrays from proof hints (round/final + blinding variants)


### 5) Compile and run verifier circuit

```bash
nargo check
nargo execute --force
```

If execution succeeds, the recursive verifier accepted the proof.

## Important Notes

1. `verifier-noir` is a **fixed-shape circuit**. Any change in inner proof config can require a
   `types.nr` update + recompilation. The `generate-noir-inputs` command auto-syncs these constants.
2. Hash config must match end-to-end: this verifier expects `HashConfig::Poseidon2` transcript and
   Merkle behavior. For other hash configs, use the matching verifier.
3. The Fiat-Shamir sponge is the Poseidon2 duplex sponge with state `[Field; 4]`, rate 96 bytes
   (3 field elements), capacity 32 bytes (1 field element). Merkle leaves and public-input hashes
   use the Poseidon2 length-IV sponge (`state[3] = n * 2^64`) matching
   `provekit/common/src/poseidon2/whir.rs::hash_message` and `poseidon2::poseidon2_hash`.
