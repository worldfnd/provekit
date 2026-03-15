# CLAUDE.md

## Project Overview

ProveKit is a zero-knowledge proof system toolkit by the World Foundation. It compiles Noir programs to R1CS constraints and generates/verifies WHIR proofs. The codebase is ~95% Rust with a Go recursive verifier.

## Architecture

```
Noir Circuit (.acir)
  ↓ [r1cs-compiler]
R1CS (A, B, C matrices) + Witness Builders
  ↓ [prover]
  1. Witness solving (layered: w1 → challenges → w2)
  2. R1CS compression (postcard blob, reduces peak memory)
  3. W1 commitment (Skyscraper/SHA256/Keccak/Blake3 Merkle tree)
  4. W2 commitment (if multi-challenge circuit)
  5. WHIR sumcheck
  ↓
NoirProof { public_inputs, whir_r1cs_proof }
  ↓ [verifier]
  1. Fiat-Shamir transcript replay
  2. Commitment verification
  3. Sumcheck verification
  4. Public input binding check
  ↓
Accept / Reject
```

### Crate Structure

**Core proof system (Rust):**
- `provekit/common` — Shared types: R1CS, SparseMatrix, Interner, PrefixCovector, WitnessBuilders, HashConfig, serialization
- `provekit/r1cs-compiler` — Noir ACIR → R1CS compilation with optimizations (binop batching, range check batching, spread table caching)
- `provekit/prover` — WHIR proving: witness solving, memory compression, commitment, sumcheck
- `provekit/verifier` — WHIR verification: transcript replay, sumcheck check, public input binding

**Cryptographic primitives:**
- `skyscraper/core` — Custom BN254 hash engine with SIMD-accelerated field arithmetic (aarch64). Registered globally at startup.
- `ntt` — Number Theoretic Transform for polynomial evaluation/interpolation. Supports interleaved polynomials.
- `poseidon2` — Poseidon2 hash function (BN254-specific). Used in R1CS compilation for Poseidon2 black box calls.

**Tooling:**
- `tooling/cli` — Main CLI for prove/verify commands
- `tooling/provekit-ffi` — C-compatible FFI bindings (iOS, Android, Python, Swift, Kotlin)
- `tooling/provekit-gnark` — gnark integration for Go interop
- `tooling/provekit-bench` — Benchmarking utilities
- `tooling/verifier-server` — HTTP server combining Rust API + Go verifier

**Go recursive verifier** (`recursive-verifier/`):
- Takes WHIR proof and produces Groth16 proof for on-chain verification via gnark
- CLI (`cmd/cli/`) and HTTP server (`cmd/server/`) modes
- R1CS must match the WHIR proof being verified; PK/VK must be generated together

## Critical Invariants

These invariants are critical for soundness. Violations can produce unsound proofs or verification failures.

### R1CS Constraint Satisfaction
```
For all constraints i: (A[i] · w) * (B[i] · w) = C[i] · w  (mod BN254 prime)
```
Changes to `noir_to_r1cs()`, WitnessBuilder variants, or R1CS optimization passes must preserve this.

### Fiat-Shamir Transcript Determinism
Prover and verifier must construct identical Fiat-Shamir transcripts. The domain separator is derived from the serialized `WhirR1CSScheme`. Any change to proof structure, commitment ordering, or message sequencing breaks transcript consistency and causes verification failure.

### Public Input Binding
```
public_inputs[i] == witness[1 + i]  for all i < num_public_inputs
```
The witness at position 0 is the constant `1`. `make_public_weight` and `compute_public_eval` use `n = num_public_inputs + 1` to account for this. Off-by-one here is a soundness vulnerability (see PR #321).

### Witness Layer Scheduling
Witness builders execute in layers. All builders depending on a `Challenge` must be in a later layer than the challenge source. Within a layer, execution order is irrelevant. Layers of type `Inverse` use Montgomery's batch inversion trick (single field inverse + multiplications). Violating layer ordering causes panics in `solve_witness_vec()`.

### Prover Message vs Prover Hint
- `prover_message`: Absorbed into Fiat-Shamir transcript — verifier derives challenges from it. Use for values that must be transcript-bound.
- `prover_hint_ark`: NOT absorbed into transcript — prover sends it but it doesn't affect challenges. Use only for values independently verified by WHIR (e.g., committed polynomial evaluations).

Misusing `prover_hint_ark` for a value that should be transcript-bound is a soundness vulnerability — a malicious prover can substitute arbitrary values without detection.

### NTT/Hash Engine Registration
```rust
provekit_common::register_ntt();  // Must be called once at startup
```
Registers the WHIR ArkNtt and Skyscraper hash engine globally. Forgetting this causes runtime panics.

## Key Types

### R1CS
```rust
pub struct R1CS {
    pub num_public_inputs: usize,
    pub interner: Interner,       // Deduplicates field elements in matrices
    pub a: SparseMatrix,          // Left constraint matrix
    pub b: SparseMatrix,          // Middle constraint matrix
    pub c: SparseMatrix,          // Right constraint matrix
}
```

### SparseMatrix
Uses delta-encoded column indices within rows (reduces serialized size ~30-50%). Key operations: `set()`, `iter_row()`, `transpose()`, `multiply()` (parallel via rayon).

### PrefixCovector / OffsetCovector
Memory-optimized covectors for zero-padded vectors. PrefixCovector stores only the non-zero prefix; OffsetCovector stores weights at an offset. Both implement `LinearForm` for MLE evaluation.

### NoirProof
```rust
pub struct NoirProof {
    pub public_inputs: PublicInputs,
    pub whir_r1cs_proof: WhirR1CSProof,  // narg_string (raw bytes) + hints
}
```
Serialized as postcard binary (`.np`) or JSON (`.json`). Hash config stored as 1-byte header.

### WitnessBuilder
~15+ variants: Constant, Sum, Product, Inverse, Challenge, DigitalDecomposition, SpiceWitnesses (RAM/ROM), LogUpInverse, BinOpLookupDenominator, etc. Each variant knows how to compute its witness value from prior witnesses.

### HashConfig
Runtime-selectable: Skyscraper (default, custom optimized), SHA256, Keccak, Blake3. Determines Merkle tree hash and Fiat-Shamir sponge.

## Build & Test

```bash
# Rust (requires nightly)
cargo fmt --all --check
cargo clippy --all-targets --all-features --verbose
cargo build --all-targets --all-features --verbose
cargo test --no-fail-fast --all-features --verbose --lib --tests --bins
cargo test --doc --all-features --verbose
cargo doc --workspace --all-features --no-deps --document-private-items  # with RUSTDOCFLAGS="--cfg doc_cfg -D warnings"

# Go (recursive-verifier/)
cd recursive-verifier && go build ./... && go test -v -cover ./...
```

Toolchain: Rust nightly (nightly-2026-03-04), edition 2021, rust-version 1.85. Go 1.24.

CI runs on `ubuntu-24.04-arm`. End-to-end tests run on self-hosted ARM64 (`provekit-build`).

## Code Conventions

### Rust

- **Formatting**: `cargo fmt`. CI enforces.
- **Linting**: `cargo clippy` with workspace-level lints: `warn` on `perf`, `complexity`, `style`, `correctness`, `suspicious`. `deny` on `missing_safety_doc`.
- **Error handling**: `anyhow::Result<T>` with `.context("description")`. Use `ensure!()` for invariant checks, `bail!()` for early returns. No `.unwrap()` or `.expect()` in library code — only in tests and CLI entry points.
- **Unsafe code**: All `unsafe` blocks must have `// SAFETY:` comment explaining the invariant. Avoid `unsafe` in proof system core (`provekit/*`) without team review.
- **Documentation**: All `pub` items need `///` doc comments. CI runs `cargo doc -D warnings`.
- **Tracing**: Use `#[instrument(skip_all)]` from `tracing` for function tracing. Do not log large objects.
- **Parallelism**: Use `rayon` for data parallelism. Do not spawn raw threads.
- **Dependencies**: Declare in root `Cargo.toml` `[workspace.dependencies]`, reference with `{ workspace = true }` in crate `Cargo.toml`.
- **Testing**: `#[test_case]` for parameterized tests, `proptest`/`quickcheck` for property-based tests. Integration tests compile Noir programs end-to-end.

### Go (recursive-verifier/)

- `gofmt`, `go vet`, `golangci-lint` must pass.
- `go mod tidy` must produce no diff.

## FFI Safety Rules (`tooling/provekit-ffi`)

- All `*const c_char` parameters must be valid null-terminated UTF-8.
- `pk_init()` must be called exactly once before any prove/verify.
- `pk_configure_memory()` must be called before `pk_init()` if using custom allocator.
- All returned `PKBuf` must be freed exactly once via `pk_free_buf()`.
- All FFI functions wrap Rust code with `catch_panic()` to prevent unwinding across the FFI boundary.
- Dual allocator modes: callback-based (host delegates alloc/dealloc) or mmap-based (swap-to-disk).

## Serialization Compatibility

- **Proof format**: `NoirProof` serialized via postcard (`.np`) or serde_json (`.json`). Hash config stored as 1-byte header.
- **Proof scheme** (`.pkp`): Serialized Prover/Verifier containing R1CS, witness builders, WHIR config.
- **SparseMatrix**: Uses delta-encoded column indices on disk. `encode_col_deltas` / `decode_col_deltas` must roundtrip correctly.
- **Breaking changes**: Do not change serialization formats without migration plan — deployed verifiers and mobile clients depend on compatibility.

## Security Rules

This is a cryptographic proof system. Correctness and soundness are critical.

- Never skip or weaken constraint checks in prover/verifier code without explicit justification.
- Sensitive field elements must use `zeroize` for cleanup.
- Do not introduce `unsafe` code in `provekit/*` without team review.
- FFI boundaries must validate all input pointers and lengths.
- Do not change serialization formats without migration plan.
- All field arithmetic is mod BN254 prime. Montgomery representation used internally by arkworks — transparent to users.

## Code Review Checklist

When reviewing PRs, check for:

- **Soundness**: Changes to constraint generation (`noir_to_r1cs`), witness builders, prover transcript messages (`prover_message` vs `prover_hint_ark`), or verification logic must not weaken soundness. Scrutinize for missing constraints, wrong witness layer ordering, or transcript inconsistencies.
- **Public input binding**: Any change to `make_public_weight`, `compute_public_eval`, or `verify_public_input_binding` must account for the constant-1 witness at position 0 (`n = num_public_inputs + 1`).
- **Transcript consistency**: Prover and verifier must produce identical Fiat-Shamir transcripts. Check that new prover messages are mirrored in verifier, and vice versa.
- **Unsafe code**: New `unsafe` blocks must have `// SAFETY:` comments. Prefer safe alternatives. Extra scrutiny for `skyscraper/` SIMD code.
- **Error handling**: No `.unwrap()` in library code. Use `anyhow::Result` with `context()`/`ensure!()`/`bail!()`.
- **Public API docs**: All new `pub` items need `///` doc comments.
- **Test coverage**: New functionality must include tests. Bug fixes must include regression tests. Property-based tests (`proptest`/`quickcheck`) preferred for mathematical operations.
- **Workspace deps**: Dependencies must be in root `Cargo.toml` `[workspace.dependencies]`.
- **Serialization**: Changes to serialized types (`NoirProof`, `R1CS`, `SparseMatrix`, `WhirR1CSProof`) must maintain backward compatibility or include migration.
- **Performance**: Changes to hot paths (NTT, polynomial ops, sparse matrix multiply, sumcheck inner loop) must not regress performance. Use `#[instrument]` for tracing.
- **FFI safety**: Changes to `provekit-ffi` must maintain panic safety (`catch_panic`), pointer validation, and `PKBuf` lifetime correctness.
- **Clippy compliance**: All clippy warnings resolved. Workspace enforces `warn` on `perf`, `complexity`, `style`, `correctness`, `suspicious`.
- **Formatting**: `cargo fmt` for Rust, `gofmt` for Go. No exceptions.

## PR Guidelines

- Branch names: `username/description` (e.g., `px/fix-verifier`).
- Keep PRs focused — one logical change per PR.
- CI must pass before merge. Do not bypass branch protection without justification.
