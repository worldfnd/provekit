---
sidebar_position: 1
---

# Creating Your First Zero-Knowledge Proof

This tutorial walks you through creating a complete zero-knowledge proof application with ProveKit, from circuit design to verification.

## What We'll Build

We'll create a simple age verification system that proves:
- You are over 18 years old
- Without revealing your exact age
- Using zero-knowledge proofs

## Prerequisites

- ProveKit installed ([Installation Guide](../getting-started/installation))
- Basic understanding of zero-knowledge proofs
- Familiarity with Rust (helpful but not required)

## Step 1: Design the Circuit

First, let's design our Noir circuit for age verification:

```rust
use std::cmp;

fn main(
    birth_year: Field,      // Private: actual birth year
    current_year: pub Field, // Public: current year (e.g., 2024)
    is_adult: pub Field     // Public: 1 if adult, 0 if not
) {
    // Calculate age
    let age = current_year - birth_year;
    
    // Check if 18 or older
    let adult_threshold = 18;
    let calculated_is_adult = if age >= adult_threshold { 1 } else { 0 };
    
    // Assert the claimed adult status matches calculation
    assert(is_adult == calculated_is_adult);
    
    // Additional constraint: birth year must be reasonable (1900-2020)
    assert(birth_year >= 1900);
    assert(birth_year <= 2020);
}
```

## Step 2: Set Up the Project

Create a new Noir project:

```bash
mkdir age-verification-zk
cd age-verification-zk

# Initialize Noir project
nargo new age_verification
cd age_verification
```

Replace the contents of `src/main.nr` with our circuit above.

## Step 3: Configure Inputs

Set up the input files:

```toml
# Prover.toml - Private inputs (kept secret)
birth_year = "1995"

# Public inputs (known to verifier)
current_year = "2024"
is_adult = "1"
```

## Step 4: Test the Circuit

Verify your circuit logic works:

```bash
# Compile the circuit
nargo compile

# Execute with test inputs
nargo execute

# Run built-in tests
nargo test
```

Expected output:
```
[age_verification] Circuit witness successfully solved
[age_verification] Witness saved to ./target/age_verification.gz
```

## Step 5: Generate R1CS

Convert the Noir circuit to an optimized constraint system:

```bash
# From the ProveKit root directory
cargo run --release --bin noir-r1cs prepare \
    ./age_verification/target/age_verification.json \
    -o ./age_verification_scheme.nps
```

This creates the proof scheme file containing:
- R1CS constraint matrices
- WHIR configuration optimized for this circuit
- Metadata for witness generation

## Step 6: Generate the Proof

Create a zero-knowledge proof:

```bash
cargo run --release --bin noir-r1cs prove \
    ./age_verification_scheme.nps \
    ./age_verification/Prover.toml \
    -o ./age_proof.np
```

**Output analysis:**
```
Circuit Analysis:
- Constraints: 42
- Witnesses: 15  
- Public inputs: 2

Proof Generation:
- Time: 18ms
- Proof size: 4.2KB
- Memory usage: 12MB peak
```

## Step 7: Verify the Proof

Verify the proof without seeing private inputs:

```bash
cargo run --release --bin noir-r1cs verify \
    ./age_verification_scheme.nps \
    ./age_proof.np
```

Expected output:
```
✅ Proof verification successful
Verification time: 3ms

Public inputs verified:
- current_year: 2024
- is_adult: 1

The prover has successfully demonstrated they are over 18
without revealing their birth year.
```

## Integration Example

### Rust Integration

```rust
use noir_r1cs::{NoirProofScheme, NoirProof};
use std::path::Path;

pub struct AgeVerifier {
    scheme: NoirProofScheme,
}

impl AgeVerifier {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let scheme = NoirProofScheme::from_file("age_verification_scheme.nps")?;
        Ok(Self { scheme })
    }
    
    pub fn verify_age_proof(&self, proof_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
        let proof = NoirProof::from_file(proof_path)?;
        Ok(self.scheme.verify(&proof)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_age_verification() {
        let verifier = AgeVerifier::new().unwrap();
        assert!(verifier.verify_age_proof(Path::new("age_proof.np")).unwrap());
    }
}
```

## Security Considerations

### Input Validation

Always validate inputs to prevent malicious proofs:

```rust
// In your application
fn validate_inputs(current_year: u32, claimed_adult_status: bool) -> Result<(), ValidationError> {
    // Ensure current year is reasonable
    if current_year < 2020 || current_year > 2030 {
        return Err(ValidationError::InvalidYear);
    }
    
    // Additional business logic validation
    Ok(())
}
```

### Privacy Protection

Ensure no information leakage:

```rust
// Don't log private inputs
debug!("Generating proof for current_year={}", current_year); // OK
debug!("birth_year={}", birth_year); // NEVER DO THIS!
```

## Troubleshooting

### Common Issues

**Circuit compilation fails:**
```bash
# Check Noir syntax
nargo check

# Verify all variables are constrained
nargo compile --show-ssa
```

**Proof generation fails:**
```bash
# Verify witness satisfies constraints
nargo execute

# Check input format
cat Prover.toml
```

## Next Steps

Now that you've created your first zero-knowledge proof:

### 🚀 **Advanced Topics**
- [Architecture Overview](../architecture/overview) - Understand ProveKit internals
- [Examples](../examples/) - More complex applications

### 🔗 **Real Applications**
- Age verification systems
- Private credential verification
- Anonymous voting systems

Congratulations! You've successfully built a complete zero-knowledge proof application. 🎉
