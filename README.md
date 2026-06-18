# ProveKit

<div align="center">

<img src="./assets/banner.png" alt="ProveKit" width="100%" />

[![CI](https://img.shields.io/github/actions/workflow/status/worldfnd/provekit/ci.yml?branch=main&style=flat-square&label=CI&logo=github)](https://github.com/worldfnd/provekit/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-nightly-e32828?style=flat-square&logo=rust)](https://rustup.rs/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](./LICENSE.md)

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Examples](./noir-examples/) · [Repository Map](#repository-map) · [Contributing](./CONTRIBUTING.md)

</div>

ProveKit is a zero-knowledge proof system toolkit that compiles [Noir](https://noir-lang.org/) programs to R1CS constraints and generates and verifies [WHIR](https://github.com/WizardOfMenlo/whir) proofs using a Spartan-based protocol. It includes custom SIMD-accelerated field arithmetic and memory-efficient algorithms for resource-constrained environments, with a complete proving and verification stack plus recursive verification support for on-chain Groth16 applications.

## Why ProveKit

- **Noir frontend:** write circuits in Noir and use ProveKit to prepare keys, prove, and verify with one CLI.
- **Post-quantum secure proofs:** produce WHIR proofs designed around post-quantum security assumptions.
- **Integration-ready surface:** use ProveKit from Swift, Kotlin, JavaScript, and Rust, or use the C-compatible FFI when you need another language.
- **Recursive verifier for on-chain Groth16:** export verifier/proof data for a recursive verifier when an on-chain Groth16 wrapper is required.

## Quick Start

### Prerequisites

Install Rust with `rustup`. This repository includes `rust-toolchain.toml`, so Cargo picks the pinned nightly automatically.

### Run a proof

The smallest end-to-end path is the [`noir-examples/basic`](./noir-examples/basic/) package:

```sh
cd noir-examples/basic
cargo run --release --bin provekit-cli prepare
cargo run --release --bin provekit-cli prove
cargo run --release --bin provekit-cli verify
```

`prepare` writes a **ProveKit Prover** key (`.pkp`) and a **ProveKit Verifier** key (`.pkv`). `prove` reads the PKP plus `Prover.toml` and writes `proof.np`. `verify` reads the PKV and the proof.

### On-chain verification (Groth16 backend)

For proofs produced with `prepare --backend groth16`, the same PKV + proof can be checked by a Solidity verifier. Two commands generate the artefacts:

```sh
# Render a circuit-specific Solidity verifier from the PKV.
cargo run --release --bin provekit-cli export-solidity \
  --pkv <circuit>.pkv \
  --template provekit/groth16/contracts/ProvekitGroth16Verifier.sol \
  --out <circuit>Verifier.sol

# Convert the proof to EVM big-endian calldata + a public-inputs file.
cargo run --release --bin provekit-cli export-evm-proof \
  --proof proof.np \
  --out-dir out/
```

`export-solidity` substitutes all `CODEGEN` markers in the in-repo template with constants from the verifying key (VK scalars, G1/G2 coordinates, gnark-style negations, public-input bases). `export-evm-proof` produces `out/proof.hex` (uncompressed `Ar‖Bs‖Krs‖Commit‖PoK` in EVM big-endian) and `out/inputs.txt` (one decimal field element per line, sized to `N_PUB`). Deploy the rendered `.sol` and call `verifyProof(bytes, uint256[N])` with those two inputs. Single-commitment circuits only for now — see [`provekit/groth16/contracts/README.md`](./provekit/groth16/contracts/README.md) for scope, constraints, and the multi-commitment roadmap.

### Trusted-setup ceremony (Groth16 backend)

`prepare --backend groth16` defaults to an **in-process single-party setup**: convenient for development, but not secure for production because one machine knows the toxic waste τ. For production-grade keys, run a multi-party Phase 2 ceremony with the [reilabs/trusted-setup](https://github.com/reilabs/trusted-setup) tool against a public Phase 1 (powers-of-tau) artifact, then import the result via `prepare --groth16-pk-in / --groth16-vk-in / --groth16-fingerprint-in`.

```sh
# 1. Export the R1CS plus a fingerprint sidecar (the .fingerprint file).
cargo run --release --bin provekit-cli export-gnark-r1cs \
  noir-examples/<circuit>/target/<circuit>.json \
  --out circuit.r1cs.json

# 2. Convert JSON → gnark binary .r1cs
#    (Go `import_r1cs` tool from https://github.com/reilabs/trusted-setup).
./import_r1cs --in circuit.r1cs.json --out circuit.r1cs

# 3. Run Phase 2 against a Phase 1 file
#    (powers-of-tau ≥ ceil(log2(num_constraints))).
./trusted-setup init --phase1 prod.ph1 --r1cs circuit.r1cs \
    --phase2 c.ph2 --srscommons c.srs
./trusted-setup contribute --phase2 c.ph2     # repeat per contributor
./trusted-setup extract-keys --r1cs circuit.r1cs --srscommons c.srs \
    --beacon <hex> --phase2 <ph2-files,...> --pk circuit.pk --vk circuit.vk

# 4. Import the ceremony output back into Provekit, binding to the R1CS
#    via the fingerprint sidecar from step 1.
cargo run --release --bin provekit-cli prepare \
  noir-examples/<circuit>/target/<circuit>.json --backend groth16 \
  --groth16-pk-in circuit.pk \
  --groth16-vk-in circuit.vk \
  --groth16-fingerprint-in circuit.r1cs.json.fingerprint \
  --pkp <circuit>.pkp --pkv <circuit>.pkv
```

**`--groth16-fingerprint-in <sidecar>` (recommended for production).** The sidecar `<out>.fingerprint` written by `export-gnark-r1cs` is the SHA3-256 of `(R1CS, CommitmentInfo)`. At `prepare` time, Provekit re-compiles the Noir source, recomputes the fingerprint from the local R1CS, and **fails loud on mismatch**. This catches the case where a ceremony was run against a different R1CS that happens to share wire/constraint counts — without the flag, shape-only validation would silently let it pass and produce non-verifying or wrong-public-input-binding proofs. Omitting the flag is supported (a warning fires) and fine for local testing, but production deployments should always pass it.

**Phase 1 files** come from public ceremonies — most commonly the Hermez/Snarkjs `powersOfTau28_hez_final_NN.ptau` series. Pick `NN ≥ ceil(log2(num_constraints))` for your circuit (e.g., `NN = 20` for a 636,683-constraint circuit). Convert the `.ptau` to a `.ph1` once via `./trusted-setup ptau --ptau <file>.ptau --phase1 prod.ph1`, then reuse it for any circuit ≤ `2^NN` constraints. The [reilabs/trusted-setup](https://github.com/reilabs/trusted-setup) tool only consumes a Phase 1 — it does not run one.

### Command reference

| Command | Purpose | Key options |
| :--- | :--- | :--- |
| `prepare` | Compile a Noir package and write prover/verifier keys | `--pkp`/`-p`, `--pkv`/`-v`, `--hash`, `--backend`, `--mmap` (Groth16 only); ceremony import: `--groth16-pk-in`, `--groth16-vk-in`, `--groth16-fingerprint-in` (Groth16 backend only); default hash: `skyscraper`, default backend: `whir` |
| `prove` | Produce `proof.np` from a prover key and inputs | `--prover`/`-p`, `--input`/`-i`, `--out`/`-o` |
| `verify` | Verify a proof against a verifier key | `--verifier`/`-v`, `--proof` |
| `export-gnark-r1cs` | Dump an R1CS to the JSON format consumed by the gnark trusted-setup importer ([reilabs/trusted-setup](https://github.com/reilabs/trusted-setup)), plus a `.fingerprint` sidecar that binds the ceremony output to this R1CS | `<program_path>` or `--pkv`, `--out`/`-o`, `--hash` |
| `export-solidity` | Render a circuit-specific Solidity verifier from a Groth16 PKV (substitutes `CODEGEN` markers in the template) | `--pkv`/`-v`, `--template`/`-t`, `--out`/`-o` |
| `export-evm-proof` | Re-emit a Groth16 `proof.np` as EVM big-endian calldata + a public-inputs file for `verifyProof(bytes, uint256[N])` | `--proof`/`-p`, `--out-dir`/`-o` |

Read the table per command: the short `-p` flag changes meaning between `prepare` and `prove`.

Available `prepare --hash` choices are `skyscraper`, `sha256`, `keccak`, `blake3`, and `poseidon2`.

Available `prepare --backend` choices are `whir` (default) and `groth16`.

## How It Works

```mermaid
graph LR
    Noir[Noir source<br/>.nr] -->|Noir frontend| ACIR[ACIR]
    ACIR -->|r1cs-compiler| R1CS[R1CS<br/>+ witness builders]
    Noir -.->|mavros| R1CS
    R1CS --> PKP[(.pkp<br/>prover key)]
    R1CS --> PKV[(.pkv<br/>verifier key)]
    Inputs[Prover.toml] --> Prover((Prover))
    PKP --> Prover
    Prover --> Proof[proof.np]
    PKV --> Verifier((Verifier))
    Proof --> Verifier
    PKV -.-> GnarkInputs[generate-gnark-inputs]
    Proof -.-> GnarkInputs
    GnarkInputs -.-> Recursive[Go/gnark<br/>recursive verifier]
    Recursive --> Groth16[Groth16 proof]
```

The default Noir frontend reads a package, produces ACIR, lowers that ACIR into R1CS, and writes `.pkp`/`.pkv` key files. Circuits that benefit from a direct R1CS frontend can use [`mavros`](https://github.com/reilabs/mavros) with `prepare --compiler mavros` and an explicit `--r1cs` file.

## Example Circuit

[`noir-examples/basic`](./noir-examples/basic/) proves knowledge of a Poseidon hash preimage:

```rust
use dep::poseidon2;

fn main(plains: [Field; 2], result: Field) {
    let hash = poseidon2::bn254::hash_2(plains);
    assert(hash == result);
}
```

For larger circuits and integration experiments, see [`noir-examples/`](./noir-examples/).

## Repository Map

| Layer | Path | Crate/package | Purpose |
| :--- | :--- | :--- | :--- |
| Common types | `provekit/common/` | `provekit-common` | Shared R1CS, witness, proof, key, serialization, and transcript utilities |
| Compiler | `provekit/r1cs-compiler/` | `provekit-r1cs-compiler` | Noir ACIR → R1CS lowering, including binop, range-check, and lookup-table handling |
| Prover | `provekit/prover/` | `provekit-prover` | Witness solving, R1CS compression, WHIR commitments, and proof generation |
| Verifier | `provekit/verifier/` | `provekit-verifier` | Fiat–Shamir replay, sumcheck verification, and public input binding |
| CLI | `tooling/cli/` | `provekit-cli` | Commands for prepare, prove, verify, inspection, and gnark input generation |
| Benchmarks | `tooling/provekit-bench/` | `provekit-bench` | Benchmark utilities and regression coverage for proving workflows |
| FFI | `tooling/provekit-ffi/` | `provekit-ffi` | C ABI bindings for Swift/iOS, Kotlin/Android, Python, JavaScript, and other FFI hosts |
| Gnark export | `tooling/provekit-gnark/` | `provekit-gnark` | Rust-side export/config bridge for recursive verification artifacts |
| Verifier server | `tooling/verifier-server/` | `verifier-server` | HTTP server that orchestrates Rust proof handling and Go verifier execution |
| NTT | `ntt/` | `ntt` | Number Theoretic Transform implementation used by polynomial evaluation paths |
| Hash engine | [`skyscraper/`](skyscraper/) | first-party Skyscraper crates | BN254 hash implementation used by the Skyscraper hash configuration |
| Recursive verifier | `recursive-verifier/` | Go module | Go + gnark verifier wrapper for Groth16 recursion |
| Examples | `noir-examples/` | Noir packages | Noir example circuits and R1CS compiler test programs |

## Advanced Usage

- **Mmap-format `.pkp`** (Groth16 only): pass `--mmap` to `prepare` to write an mmap-friendly `.pkp` instead of the zstd-compressed default. Larger artifact (no compression, raw in-memory layout for curve-point and R1CS arrays), but near-instant load — the kernel pages bytes in lazily as the MSM touches them, matching rapidsnark's zkey-loading model. Both layouts share the `.pkp` extension; `prove` auto-detects via the file's `MMAP` sentinel.
- **Direct R1CS frontend:** after generating Mavros artifacts, call `provekit-cli prepare --compiler mavros <artifacts.json> --r1cs <r1cs.bin>`.
- **Recursive verifier inputs:** `provekit-cli generate-gnark-inputs <verifier.pkv> <proof.np>` writes `params_for_recursive_verifier` and `r1cs.json` by default; use `--params` and `--r1cs` to override those paths.
- **Inspection commands:** use `circuit-stats` for Noir ACIR/R1CS structure, `analyze-pkp` for Noir prover-key size breakdowns, and `show-inputs` for public inputs.
- **FFI integration:** start in [`tooling/provekit-ffi/`](tooling/provekit-ffi/) for C ABI headers, mobile build targets, and host-language examples.
- **Profiling:** use the built-in allocator stats from the CLI, or build with Tracy support when interactive profiling is needed.

## Project Status

ProveKit is under active development. For the current stable interface, use the `v1` branch; `main` may include breaking changes while new proof and key formats are being developed.

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for development guidelines and use the [issue tracker](https://github.com/worldfnd/provekit/issues) for bugs, feature requests, and design discussion.

## Acknowledgements

- [**WHIR**](https://github.com/WizardOfMenlo/whir) — polynomial commitment scheme and sumcheck protocol used by the proof system.
- [**Spongefish**](https://github.com/arkworks-rs/spongefish) — Fiat–Shamir transcript library used for challenge derivation.
- [**gnark-skyscraper**](https://github.com/reilabs/gnark-skyscraper) — Go implementation used by the recursive verifier to reproduce Skyscraper commitments.
- [**Noir**](https://github.com/noir-lang/noir) — ZK DSL compiled by ProveKit.

## License

Released under the [MIT License](./LICENSE.md). Copyright (c) 2026 World Foundation.
