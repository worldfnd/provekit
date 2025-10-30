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

Use the `spark-cli` tool in `tooling/spark-cli`:

```bash
# Prove
cargo run --release --bin spark-cli -- prove --noir-proof-scheme ./noir-provekit-prover.pkp --noir-proof ./noir-proof.np 

# Verify
cargo run --release --bin spark-cli -- verify --spark-proof spark_proof.json --noir-proof ./noir-proof.np 
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
