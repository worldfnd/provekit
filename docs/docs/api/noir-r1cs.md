---
sidebar_position: 1
---

# noir-r1cs API Reference

Complete API documentation for the `noir-r1cs` crate, the core component of ProveKit.

## CLI Commands

### `prepare`

Prepares a proof scheme from a compiled Noir circuit.

```bash
cargo run --bin noir-r1cs prepare [OPTIONS] <CIRCUIT> 

ARGS:
    <CIRCUIT>    Path to the compiled Noir circuit (.json file)

OPTIONS:
    -o, --output <FILE>    Output file for the proof scheme (.nps)
    --optimize             Enable constraint optimizations
    --field <FIELD>        Target field (bn254, bls12-381) [default: bn254]
```

**Example:**
```bash
cargo run --bin noir-r1cs prepare ./circuit.json -o ./scheme.nps --optimize
```

### `prove`

Generates a zero-knowledge proof using a prepared scheme.

```bash
cargo run --bin noir-r1cs prove [OPTIONS] <SCHEME> <INPUTS>

ARGS:
    <SCHEME>    Path to the proof scheme (.nps file)
    <INPUTS>    Path to the input values (.toml file)

OPTIONS:
    -o, --output <FILE>    Output file for the proof (.np)
    --profile              Enable performance profiling
    --parallel <NUM>       Number of parallel threads
```

**Example:**
```bash
cargo run --bin noir-r1cs prove ./scheme.nps ./inputs.toml -o ./proof.np
```

### `verify`

Verifies a zero-knowledge proof.

```bash
cargo run --bin noir-r1cs verify [OPTIONS] <SCHEME> <PROOF>

ARGS:
    <SCHEME>    Path to the proof scheme (.nps file)
    <PROOF>     Path to the proof (.np file)

OPTIONS:
    --verbose              Show detailed verification steps
    --benchmark            Measure verification time
```

**Example:**
```bash
cargo run --bin noir-r1cs verify ./scheme.nps ./proof.np --verbose
```

## Library API

### `NoirProofScheme`

Main interface for working with Noir circuits and generating proofs.

```rust
pub struct NoirProofScheme {
    // Private fields
}

impl NoirProofScheme {
    /// Load a proof scheme from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error>;
    
    /// Create a proof scheme from a Noir program
    pub fn from_program(program: ProgramArtifact) -> Result<Self, Error>;
    
    /// Generate a proof from input values
    pub fn prove<P: AsRef<Path>>(&self, inputs: P) -> Result<NoirProof, Error>;
    
    /// Verify a proof
    pub fn verify(&self, proof: &NoirProof) -> Result<bool, Error>;
    
    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats;
}
```

### `NoirProof`

Represents a generated zero-knowledge proof.

```rust
pub struct NoirProof {
    // Private fields
}

impl NoirProof {
    /// Load a proof from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error>;
    
    /// Save a proof to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>;
    
    /// Get the public inputs
    pub fn public_inputs(&self) -> &[FieldElement];
    
    /// Get proof size in bytes
    pub fn size(&self) -> usize;
}
```

## Examples

### Basic Usage

```rust
use noir_r1cs::{NoirProofScheme, NoirProof};

// Load a proof scheme
let scheme = NoirProofScheme::from_file("circuit.nps")?;

// Generate a proof
let proof = scheme.prove("inputs.toml")?;

// Verify the proof
assert!(scheme.verify(&proof)?);

// Save the proof
proof.to_file("proof.np")?;
```

### Advanced Usage

```rust
use noir_r1cs::{NoirProofScheme, R1CS, FieldElement};

// Create proof scheme from Noir program
let program = load_noir_program("circuit.json")?;
let scheme = NoirProofScheme::from_program(program)?;

// Get circuit statistics
let stats = scheme.stats();
println!("Circuit has {} constraints", stats.num_constraints);

// Generate multiple proofs
let inputs = ["alice.toml", "bob.toml", "charlie.toml"];
let proofs: Vec<NoirProof> = inputs
    .iter()
    .map(|input| scheme.prove(input))
    .collect::<Result<Vec<_>, _>>()?;

// Batch verify
for (i, proof) in proofs.iter().enumerate() {
    assert!(scheme.verify(proof)?, "Proof {} failed verification", i);
}
```

## Error Handling

### `Error`

Main error type for the `noir-r1cs` crate.

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Circuit compilation error: {0}")]
    Compilation(String),
    
    #[error("Witness generation error: {0}")]
    WitnessGeneration(String),
    
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),
    
    #[error("Proof verification error: {0}")]
    ProofVerification(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
```

## Configuration

### Environment Variables

- `NOIR_R1CS_LOG`: Set log level (`debug`, `info`, `warn`, `error`)
- `NOIR_R1CS_THREADS`: Override number of parallel threads
- `NOIR_R1CS_MEMORY_LIMIT`: Set memory limit for large circuits

### Feature Flags

```toml
[dependencies]
noir-r1cs = { version = "0.1", features = ["parallel", "optimized"] }

# Available features:
# - parallel: Enable multi-threading
# - optimized: Use optimized implementations
# - serde: Enable serialization support
# - cli: Include CLI tools
```

## Performance Tips

### Memory Usage
- Use streaming for large witnesses
- Enable memory mapping for huge circuits
- Monitor peak memory usage

### Parallelization
- Set `NOIR_R1CS_THREADS` to number of CPU cores
- Use batch verification for multiple proofs
- Consider proof generation parallelization

### Optimization
- Enable `--optimize` flag for constraint optimization
- Use release builds for production
- Profile with `--profile` flag for bottleneck identification

## Next Steps

- [Quick Start Guide](../getting-started/quick-start) - Basic usage tutorial
- [Architecture Overview](../architecture/overview) - System design
- [Examples](../examples/poseidon-hash) - Working code samples
