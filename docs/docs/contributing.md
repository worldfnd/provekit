---
sidebar_position: 10
---

# Contributing to ProveKit

Thank you for your interest in contributing to ProveKit! This guide will help you get started with contributing to the project.

## Quick Links

- **GitHub Repository**: [worldfnd/ProveKit](https://github.com/worldfnd/ProveKit)
- **Issue Tracker**: [Issues](https://github.com/worldfnd/ProveKit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/worldfnd/ProveKit/discussions)
- **Roadmap**: [ROADMAP.md](https://github.com/worldfnd/ProveKit/blob/main/ROADMAP.md)

## Ways to Contribute

### 🐛 Bug Reports
Report bugs, performance issues, or unexpected behavior

### 💡 Feature Requests  
Suggest new features or improvements to existing functionality

### 📝 Documentation
Improve documentation, add examples, or fix typos

### 🔧 Code Contributions
Implement new features, fix bugs, or optimize performance

### 🧪 Testing
Write tests, improve test coverage, or test on new platforms

### 📦 Ecosystem
Create bindings, integrations, or applications using ProveKit

## Getting Started

### 1. Set Up Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/ProveKit.git
cd ProveKit

# Install dependencies
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
noirup --version nightly-2025-05-28

# Build and test
cargo build
cargo test
```

### 2. Understand the Codebase

```
ProveKit/
├── noir-r1cs/          # Main proof system
├── skyscraper/         # Hash function
├── block-multiplier/   # Field arithmetic  
├── hla/               # Assembly generation
├── fp-rounding/       # Platform support
├── noir-examples/     # Example circuits
└── docs/             # Documentation
```

### 3. Find Issues to Work On

Look for issues labeled:
- `good first issue` - Great for newcomers
- `help wanted` - Community help needed
- `documentation` - Documentation improvements
- `performance` - Optimization opportunities

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 2. Make Changes

Follow our coding standards:

```rust
// Use descriptive names
fn generate_proof_for_circuit(circuit: &R1CS) -> Result<Proof, ProofError> {
    // Implementation
}

// Document public APIs
/// Generates a zero-knowledge proof for the given R1CS circuit.
///
/// # Arguments
/// * `circuit` - The R1CS constraint system
/// * `witness` - The satisfying witness
///
/// # Returns
/// A `Result` containing the generated proof or an error
///
/// # Example
/// ```rust
/// let proof = generate_proof(&circuit, &witness)?;
/// ```
pub fn generate_proof(circuit: &R1CS, witness: &Witness) -> Result<Proof, ProofError> {
    // Implementation
}
```

### 3. Test Your Changes

```bash
# Run all tests
cargo test

# Run specific component tests
cargo test -p noir-r1cs

# Run benchmarks
cargo bench

# Check formatting and linting
cargo fmt
cargo clippy

# Test on examples
cd noir-examples/poseidon-rounds
nargo compile
cargo run --release --bin noir-r1cs prove ...
```

### 4. Commit and Push

```bash
git add .
git commit -m "feat: add support for custom hash functions

- Implement HashFunction trait
- Add registration mechanism  
- Update documentation
- Add tests for custom hash integration

Fixes #123"

git push origin feature/your-feature-name
```

### 5. Create Pull Request

- Use the PR template
- Link related issues
- Describe changes clearly
- Include performance impact if applicable

## Coding Standards

### Rust Style

We follow standard Rust conventions:

```rust
// Use `cargo fmt` for formatting
cargo fmt

// Fix `cargo clippy` warnings
cargo clippy --all-targets --all-features

// Prefer Result over panic
fn parse_input(input: &str) -> Result<Field, ParseError> {
    // Use ? operator for error propagation
    let value = input.parse::<u64>()?;
    Ok(Field::from(value))
}

// Use descriptive error types
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    
    #[error("Witness generation failed")]
    WitnessGeneration,
    
    #[error("Proof generation failed: {source}")]
    ProofGeneration {
        #[from]
        source: whir::Error,
    },
}
```

### Documentation

Document all public APIs:

```rust
/// A zero-knowledge proof system optimized for mobile devices.
///
/// ProveKit provides efficient proof generation and verification for
/// R1CS constraint systems using the WHIR polynomial commitment scheme.
///
/// # Examples
///
/// ```rust
/// use provekit::{NoirProofScheme, NoirProof};
///
/// let scheme = NoirProofScheme::from_file("circuit.json")?;
/// let proof = scheme.prove("inputs.toml")?;
/// assert!(scheme.verify(&proof)?);
/// ```
pub struct NoirProofScheme {
    // Implementation
}
```

## Component-Specific Guidelines

### noir-r1cs

- Maintain compatibility with specific Noir version
- Optimize constraint generation
- Ensure witness satisfaction
- Test with various circuit patterns

### skyscraper

- Focus on hash function performance
- Maintain cryptographic security properties
- Test on target hardware (ARM64)
- Benchmark against alternatives

### block-multiplier  

- Preserve mathematical correctness
- Optimize for target architectures
- Maintain assembly code quality
- Test with property-based testing

### hla

- Keep assembly generation clean
- Support instruction interleaving
- Maintain register allocation efficiency
- Test generated code correctness

## Review Process

### What We Look For

1. **Correctness**: Does the code work as intended?
2. **Performance**: Is it optimized for the target use case?
3. **Security**: Are there any security implications?
4. **Maintainability**: Is the code clean and well-documented?
5. **Testing**: Are there adequate tests?
6. **Compatibility**: Does it maintain API compatibility?

### Review Timeline

- **Initial Response**: Within 2-3 days
- **Full Review**: Within 1 week for smaller changes
- **Complex Features**: May take 2-3 weeks for thorough review

## Community Guidelines

### Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct):

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn and contribute
- Maintain a professional environment

### Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Requests**: Code review and development discussion

## Getting Help

### Resources

- [Architecture Overview](./architecture/overview) - Understand the system
- [Quick Start](./getting-started/quick-start) - Basic usage tutorial
- [Examples](./examples/poseidon-hash) - Working code samples

### Ask Questions

- **GitHub Discussions**: General questions about contributing
- **GitHub Issues**: Specific bugs or feature discussions
- **Code Comments**: Ask for clarification in pull requests

## Thank You! 

Every contribution helps make ProveKit better for the zero-knowledge proof community. Whether you're fixing a typo, optimizing performance, or adding major features, your work is appreciated! 🙏

---

Ready to contribute? Start by exploring our [good first issues](https://github.com/worldfnd/ProveKit/labels/good%20first%20issue) or [join the discussion](https://github.com/worldfnd/ProveKit/discussions)!
