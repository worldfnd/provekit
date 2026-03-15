# CLAUDE.md

## Project Overview

ProveKit is a zero-knowledge proof system toolkit by the World Foundation. It compiles Noir programs to R1CS constraints and generates/verifies WHIR proofs. The codebase is ~95% Rust with a Go recursive verifier.

## Architecture

```
Noir Program → [r1cs-compiler] → R1CS → [prover: WHIR] → Proof → [verifier] → Accept/Reject
```

**Core crates:** `provekit/common`, `provekit/r1cs-compiler`, `provekit/prover`, `provekit/verifier`
**Crypto primitives:** `skyscraper/*` (BN254 field ops), `ntt` (number theoretic transform), `poseidon2` (hash)
**Tooling:** `tooling/cli`, `tooling/provekit-ffi` (C/Swift/Kotlin/Python bindings), `tooling/verifier-server`
**Go verifier:** `recursive-verifier/` (gnark-based WHIR verification)

## Build & Test

```bash
# Rust (requires nightly)
cargo fmt --all --check
cargo clippy --all-targets --all-features
cargo build --all-targets --all-features
cargo test --no-fail-fast --all-features --lib --tests --bins
cargo test --doc --all-features

# Go (recursive-verifier/)
cd recursive-verifier && go build ./... && go test -v -cover ./...
```

Toolchain: Rust nightly (nightly-2026-03-04), Go 1.24.

## Code Conventions

### Rust

- Use `cargo fmt` and `cargo clippy`. CI enforces both — clippy warnings are errors.
- Error handling: use `anyhow::Result<T>` with `.context("description")` for adding context. Do not use `.unwrap()` or `.expect()` in library code — only in tests and CLI entry points.
- All `unsafe` blocks must have a `// SAFETY:` comment explaining the invariant. CI denies missing safety docs.
- All public items must have `///` doc comments. CI runs `cargo doc` with `-D warnings`.
- Use `#[instrument(skip_all)]` from `tracing` for performance-critical function tracing. Do not log large objects.
- Prefer `rayon` for parallelism. Do not spawn raw threads.
- Use workspace dependencies from root `Cargo.toml` — do not add crate-specific dependency versions.
- Tests use `#[test_case]` for parameterized tests, `proptest`/`quickcheck` for property-based tests.

### Go (recursive-verifier/)

- Run `gofmt`, `go vet`, and `golangci-lint` before submitting.
- Keep `go.mod` tidy (`go mod tidy` must produce no diff).

## Security Rules

This is a cryptographic proof system. Correctness and soundness are critical.

- Never skip or weaken constraint checks in prover/verifier code without explicit justification.
- Sensitive field elements must use `zeroize` for cleanup.
- Do not introduce `unsafe` code in the proof system core (`provekit/*`) without team review.
- FFI boundaries (`tooling/provekit-ffi`) must validate all input pointers and lengths.
- Do not change serialization formats (`postcard`, proof encoding) without migration plan — deployed verifiers depend on compatibility.

## Code Review Checklist

When reviewing PRs, check for:

- **Soundness**: Changes to constraint generation, prover, or verifier must not weaken soundness guarantees. Any modification to R1CS compilation, witness generation, or proof verification logic must be scrutinized for missing constraints or bypassed checks.
- **Unsafe code**: New `unsafe` blocks must have `// SAFETY:` comments. Prefer safe alternatives.
- **Error handling**: No `.unwrap()` in library code. Use `anyhow::Result` with context.
- **Public API docs**: All new `pub` items need `///` doc comments.
- **Test coverage**: New functionality must include tests. Bug fixes must include regression tests.
- **Workspace deps**: Dependencies must be declared in root `Cargo.toml` `[workspace.dependencies]`, not inline in crate `Cargo.toml` files.
- **Performance**: Changes to hot paths (NTT, polynomial operations, matrix multiplication) must not regress performance. Use `#[instrument]` for tracing.
- **Clippy compliance**: All clippy warnings must be resolved. The workspace enforces `warn` on `perf`, `complexity`, `style`, `correctness`, and `suspicious` lints.
- **Formatting**: `cargo fmt` for Rust, `gofmt` for Go. No exceptions.

## PR Guidelines

- Branch names: use prefix format like `username/description` (e.g., `px/fix-verifier`).
- Keep PRs focused — one logical change per PR.
- CI must pass before merge. Do not bypass branch protection without justification.
