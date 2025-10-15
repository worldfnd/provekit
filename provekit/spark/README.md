# ProveKit SPARK

SPARK (Sparse Polynomial Argument of Knowledge) prover and verifier implementation for ProveKit.

## Structure

-   `src/types.rs` - Type definitions (proof, request, matrices, memory)
-   `src/prover.rs` - Prover implementation and trait
-   `src/verifier.rs` - Verifier implementation and trait
-   `src/preprocessing.rs` - R1CS to SPARK matrix conversion
-   `src/sumcheck.rs` - Sumcheck protocol (prover + verifier)
-   `src/gpa.rs` - Grand Product Argument (prover + verifier)
-   `src/memory.rs` - Memory checking (rowwise + colwise)
-   `src/utils.rs` - Utilities (I/O, memory calculation, IO patterns)

## Usage

### As a Library

```rust
use provekit_spark::{
    SPARKProver, SPARKProverScheme, SPARKVerifier, SPARKVerifierScheme,
    deserialize_r1cs, deserialize_request,
};

// Proving
let r1cs = deserialize_r1cs("path/to/r1cs.json")?;
let request = deserialize_request("path/to/request.json")?;
let scheme = SPARKProverScheme::new_for_r1cs(&r1cs);
let proof = scheme.prove(&r1cs, &request)?;

// Verifying
let scheme = SPARKVerifierScheme::from_proof(&proof);
scheme.verify(&proof, &request)?;
```

### As a CLI

Use the `spark-cli` tool in `tooling/spark-cli`:

```bash
# Prove
cargo run -p spark-cli -- prove \
  --r1cs path/to/r1cs.json \
  --request path/to/request.json \
  --output proof.json

# Verify
cargo run -p spark-cli -- verify \
  --proof proof.json \
  --request request.json
```

### Test Utilities

Generate test R1CS and request files:

```bash
cargo run -p provekit-spark --bin generate_test_r1cs
cargo run -p provekit-spark --bin generate_test_request
```

## Architecture

The SPARK implementation follows a trait-based design:

-   **SPARKProver**: Trait for proving, implemented by SPARKProverScheme
-   **SPARKVerifier**: Trait for verification, implemented by SPARKVerifierScheme

The prover and verifier share common types and utilities but are otherwise independent, allowing for easy testing and extension.
