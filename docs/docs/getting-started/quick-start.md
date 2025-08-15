---
sidebar_position: 2
---

# Quick Start

Get up and running with ProveKit in under 10 minutes! This guide walks you through creating your first zero-knowledge proof.

## Overview

We'll build a simple proof for a Poseidon hash circuit:
1. Write a Noir circuit
2. Compile to R1CS 
3. Generate a proof
4. Verify the proof
5. (Optional) Recursive verification in Gnark

## Step 1: Create a Noir Circuit

Navigate to the examples directory:

```bash
cd noir-examples/poseidon-rounds
```

Examine the circuit (`src/main.nr`):

```rust
use std::hash::poseidon;

fn main(x: Field, y: pub Field) {
    let result = poseidon::bn254::hash_2([x, x]);
    assert(result == y);
}
```

This circuit:
- Takes a private input `x` and public input `y`
- Computes `poseidon_hash(x, x)`
- Asserts the result equals `y`

## Step 2: Compile the Circuit

Compile the Noir circuit to ACIR:

```bash
nargo compile
```

This creates `target/poseidon_rounds.json` containing the compiled circuit.

## Step 3: Prepare the Proof Scheme

Convert the ACIR to an optimized R1CS representation:

```bash
cargo run --release --bin noir-r1cs prepare \
    ./target/poseidon_rounds.json \
    -o ./noir-proof-scheme.nps
```

This creates `noir-proof-scheme.nps` containing:
- R1CS constraint matrices (A, B, C)
- WHIR configuration
- Witness generation metadata

## Step 4: Set Up Inputs

Edit `Prover.toml` to set your inputs:

```toml
x = "123"
y = "0x2a7a3d3b5e8e7c9a1d5f2b4c6e8a9c1e3f5d7b9a1c3e5f7d9b1a3c5e7f9d1b3a"
```

Where `y` should be `poseidon_hash(123, 123)`. You can compute this with:

```bash
# Use Noir to compute the expected output
nargo execute
cat target/Prover.toml  # Will show the computed y value
```

## Step 5: Generate the Proof

Create a zero-knowledge proof:

```bash
cargo run --release --bin noir-r1cs prove \
    ./noir-proof-scheme.nps \
    ./Prover.toml \
    -o ./noir-proof.np
```

This generates `noir-proof.np` containing the WHIR-GR1CS proof.

**Expected output:**
```
R1CS: 128 constraints, 256 witnesses
Proof generation time: 45ms
Proof size: 8.2KB
```

## Step 6: Verify the Proof

Verify the proof is valid:

```bash
cargo run --release --bin noir-r1cs verify \
    ./noir-proof-scheme.nps \
    ./noir-proof.np
```

**Expected output:**
```
✅ Proof verification successful
Verification time: 12ms
```

## Step 7: (Optional) Recursive Verification

For advanced use cases, verify the proof recursively in Gnark:

```bash
# Generate Gnark inputs
cargo run --release --bin noir-r1cs generate-gnark-inputs \
    ./noir-proof-scheme.nps \
    ./noir-proof.np

# Run Gnark verification
cd ../../gnark-whir
go run .
```

This creates a Groth16 proof that recursively verifies your original proof.

## Performance Notes

### Benchmark Results (Apple M2)
| Operation | Time | Notes |
|-----------|------|-------|
| Circuit compilation | ~500ms | One-time setup |
| Proof generation | ~45ms | Per proof |
| Proof verification | ~12ms | Per verification |
| Proof size | ~8KB | Constant for this circuit |

### Scaling
- **Constraint growth**: Linear with circuit size
- **Proof time**: O(n log n) where n = constraints  
- **Proof size**: Logarithmic in constraint count
- **Verification**: Constant time regardless of circuit size

## Next Steps

Now that you've created your first proof, explore:

### 📚 **Learn More**
- [Architecture Overview](../architecture/overview) - Understand how ProveKit works
- [Tutorials](../tutorials/basic-proof) - Advanced circuit patterns

### 🚀 **Examples** 
- [Poseidon Hash](../examples/poseidon-hash) - Hash function proofs
- [Basic Examples](../../noir-examples/) - More code samples

## Troubleshooting

### Common Issues

**"Failed to compile circuit"**
```bash
# Check Noir version
nargo --version
# Should be nightly-2025-05-28

# Update if needed
noirup --version nightly-2025-05-28
```

**"Proof generation failed"**
```bash
# Verify inputs are correct
cat Prover.toml

# Check for constraint satisfaction
nargo execute
```

### Getting Help

- [GitHub Issues](https://github.com/worldfnd/ProveKit/issues) - Bug reports
- [Discussions](https://github.com/worldfnd/ProveKit/discussions) - Questions
- [Examples](https://github.com/worldfnd/ProveKit/tree/main/noir-examples) - More code samples

Congratulations! You've successfully created your first zero-knowledge proof with ProveKit. 🎉
