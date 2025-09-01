# ProveKit

A modular zero-knowledge proof toolkit optimized for mobile devices.

## Requirements

This project makes use of Noir's `nargo` to compile circuits and generate test artifacts. Make sure to walk through the [Quick Start](https://noir-lang.org/docs/getting_started/quick_start#noir) section to install the noir toolchain. Note that we require a specific version of the toolchain, so make sure to override the version with the following command.

```sh
noirup --version nightly-2025-05-28
```

## Demo instructions

Compile the Noir circuit:

```sh
cd noir-examples/poseidon-rounds
nargo compile
```

Generate the Noir Proof Scheme:

```sh
cargo run --release --bin provekit-cli prepare ./target/basic.json -o ./noir-proof-scheme.nps
```

Generate the Noir Proof using the input Toml:

```sh
cargo run --release --bin provekit-cli prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
```

Verify the Noir Proof:

```sh
cargo run --release --bin provekit-cli verify ./noir-proof-scheme.nps ./noir-proof.np
```

Generate inputs for Gnark circuit:

```sh
cargo run --release --bin provekit-cli generate-gnark-inputs ./noir-proof-scheme.nps ./noir-proof.np
```

Recursively verify in a Gnark proof (reads the proof from `../ProveKit/prover/proof`):

```sh
cd ../../recursive-verifier
go run .
```

Benchmark against Barretenberg:

```sh
cd noir-examples/poseidon-rounds
cargo run --release --bin provekit-cli prepare ./target/basic.json -o ./scheme.nps
hyperfine 'nargo execute && bb prove -b ./target/basic.json -w ./target/basic.gz -o ./target' '../../target/release/provekit-cli prove ./scheme.nps ./Prover.toml'
```

Profile

```sh
samply record -r 10000 -- ./target/release/provekit-cli prove ./noir-proof-scheme.nps ./noir-examples/poseidon-rounds/Prover.toml -o ./noir-proof.np
```

## Benchmarking

Run the benchmark suite:

```sh
cargo test -p provekit-bench --bench bench
```

## Architecture

ProveKit follows a modular architecture with clear separation of concerns:

### Core Modules
- **`provekit/common/`** - Shared utilities, core types, and R1CS abstractions
- **`provekit/r1cs-compiler/`** - R1CS compilation logic and Noir integration  
- **`provekit/prover/`** - Proving functionality with witness generation
- **`provekit/verifier/`** - Verification functionality

### Tooling
- **`tooling/cli/`** - Command-line interface (`provekit-cli`)
- **`tooling/provekit-bench/`** - Benchmarking infrastructure
- **`tooling/provekit-gnark/`** - Gnark integration utilities

### High-Performance Components
- **`skyscraper/`** - Optimized field arithmetic for M31/CM31 fields
- **`playground/`** - Research and experimental implementations

### Examples & Tests
- **`noir-examples/`** - Example circuits and test programs
- **`gnark-whir/`** - Go-based recursive verification using Gnark

## Dependencies

This project depends on the following libraries, which are developed in lockstep:

- [🌪️ WHIR](https://github.com/WizardOfMenlo/whir)
- [Spongefish](https://github.com/arkworks-rs/spongefish)
- [gnark-skyscraper](https://github.com/reilabs/gnark-skyscraper)
- [recursive-verifier](./recursive-verifier/README.md)
- [noir](https://github.com/noir-lang/noir)
