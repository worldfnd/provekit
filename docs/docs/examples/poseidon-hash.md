---
sidebar_position: 1
---

# Poseidon Hash Example

This example demonstrates how to create zero-knowledge proofs for Poseidon hash computations using ProveKit.

## Overview

We'll create a circuit that:
1. Takes a private input value
2. Computes its Poseidon hash
3. Proves knowledge of the preimage without revealing it

## Circuit Implementation

```rust
// src/main.nr
use std::hash::poseidon;

fn main(
    preimage: Field,        // Private: the value we're hashing
    hash_output: pub Field  // Public: the expected hash result
) {
    // Compute Poseidon hash of the preimage
    let computed_hash = poseidon::bn254::hash_1([preimage]);
    
    // Assert that the computed hash matches the expected output
    assert(computed_hash == hash_output);
}
```

## Setting Up the Project

Create a new Noir project:

```bash
mkdir poseidon-example
cd poseidon-example
nargo new poseidon_circuit
cd poseidon_circuit
```

Replace `src/main.nr` with the circuit above.

## Input Configuration

Create your input file (`Prover.toml`):

```toml
# Private input (secret)
preimage = "12345"

# Public input (known to verifier)
hash_output = "0x1234567890abcdef..." # Computed Poseidon hash
```

To compute the correct hash output:

```bash
# Let Noir compute it for you
nargo execute

# Check the computed values
cat target/Prover.toml
```

## Generating the Proof

### Step 1: Compile the Circuit

```bash
nargo compile
```

### Step 2: Prepare the Proof Scheme

```bash
cargo run --release --bin noir-r1cs prepare \
    ./target/poseidon_circuit.json \
    -o ./poseidon_scheme.nps
```

### Step 3: Generate the Proof

```bash
cargo run --release --bin noir-r1cs prove \
    ./poseidon_scheme.nps \
    ./Prover.toml \
    -o ./poseidon_proof.np
```

### Step 4: Verify the Proof

```bash
cargo run --release --bin noir-r1cs verify \
    ./poseidon_scheme.nps \
    ./poseidon_proof.np
```

## Expected Output

```
Circuit Analysis:
- Constraints: 156
- Witnesses: 89
- Public inputs: 1

Proof Generation:
- Time: 28ms
- Proof size: 6.8KB
- Memory usage: 15MB peak

✅ Proof verification successful
Verification time: 8ms
```

## Advanced Examples

### Multiple Inputs

```rust
// Hash multiple values
fn main(
    input1: Field,
    input2: Field,
    input3: Field,
    hash_output: pub Field
) {
    let computed_hash = poseidon::bn254::hash_3([input1, input2, input3]);
    assert(computed_hash == hash_output);
}
```

### Hash Chain

```rust
// Prove knowledge of a hash chain
fn main(
    secret: Field,
    num_iterations: Field,
    final_hash: pub Field
) {
    let mut current = secret;
    
    for _i in 0..num_iterations {
        current = poseidon::bn254::hash_1([current]);
    }
    
    assert(current == final_hash);
}
```

### Merkle Tree Verification

```rust
// Verify membership in a Merkle tree
fn main(
    leaf: Field,
    merkle_path: [Field; 8],  // Path to root
    merkle_root: pub Field    // Public root
) {
    let mut current = leaf;
    
    for i in 0..8 {
        current = poseidon::bn254::hash_2([current, merkle_path[i]]);
    }
    
    assert(current == merkle_root);
}
```

## Performance Analysis

### Circuit Complexity
| Hash Inputs | Constraints | Proof Time | Proof Size |
|-------------|-------------|------------|------------|
| 1 input | 156 | 28ms | 6.8KB |
| 2 inputs | 198 | 32ms | 7.2KB |
| 3 inputs | 240 | 36ms | 7.6KB |

### Scaling Behavior
- **Linear growth**: Each additional input adds ~42 constraints
- **Proof time**: Scales sub-linearly with constraint count
- **Proof size**: Logarithmic scaling (efficient for large circuits)

## Use Cases

### 1. Password Verification
Prove you know a password without revealing it:

```rust
fn main(password: Field, password_hash: pub Field) {
    let computed_hash = poseidon::bn254::hash_1([password]);
    assert(computed_hash == password_hash);
}
```

### 2. Commitment Schemes
Create commitments with optional blinding factors:

```rust
fn main(
    value: Field, 
    nonce: Field, 
    commitment: pub Field
) {
    let computed_commitment = poseidon::bn254::hash_2([value, nonce]);
    assert(computed_commitment == commitment);
}
```

### 3. Private Set Membership
Prove an element belongs to a set without revealing which one:

```rust
fn main(
    secret_element: Field,
    set_root: pub Field,
    merkle_path: [Field; 8]
) {
    // Verify secret_element is in the Merkle tree with root set_root
    let mut current = secret_element;
    for i in 0..8 {
        current = poseidon::bn254::hash_2([current, merkle_path[i]]);
    }
    assert(current == set_root);
}
```

## Troubleshooting

### Common Issues

**Hash mismatch errors:**
```bash
# Ensure you're using the same Poseidon implementation
# Let Noir compute the expected hash:
nargo execute
```

**Performance issues:**
```bash
# Use release mode for better performance
cargo build --release

# Enable optimizations
cargo run --release --bin noir-r1cs prepare ... --optimize
```

## Next Steps

### Advanced Topics
- [Basic Proof Tutorial](../tutorials/basic-proof) - Age verification example
- [Architecture Overview](../architecture/overview) - System design

### Related Examples
- [SHA-256 Verification](./sha256) - Alternative hash function
- More examples in the [noir-examples](https://github.com/worldfnd/ProveKit/tree/main/noir-examples) directory

### Resources
- [Poseidon Paper](https://eprint.iacr.org/2019/458.pdf) - Original research
- [Noir Documentation](https://noir-lang.org/) - Noir language reference
- [WHIR Paper](https://eprint.iacr.org/2024/1586.pdf) - Proof system details
