# ProveKit

A modular zero-knowledge proof toolkit optimized for mobile devices.

## Requirements

This project makes use of Noir's `nargo` to compile circuits and generate test artifacts. Make sure to walk through the [Quick Start](https://noir-lang.org/docs/getting_started/quick_start#noir) section to install the noir toolchain. Note that we require a specific version of the toolchain, so make sure to override the version with the following command.

```sh
noirup --version v1.0.0-beta.11
```

## Demo instructions

> _NOTE:_ The example below is being run for single example `poseidon-rounds`. You can use different example to run same commands.

Compile the Noir circuit:

```sh
cd noir-examples/poseidon-rounds
nargo compile
```

Prepare the Noir program (generates prover and verifier files):

```sh
cargo run --release --bin provekit-cli prepare ./target/basic.json --pkp ./prover.pkp --pkv ./verifier.pkv
```

Generate the Noir Proof using the input Toml:

```sh
cargo run --release --bin provekit-cli prove ./prover.pkp ./Prover.toml -o ./proof.np
```

Verify the Noir Proof:

```sh
cargo run --release --bin provekit-cli verify ./verifier.pkv ./proof.np
```

Generate inputs for Gnark circuit:

```sh
cargo run --release --bin provekit-cli generate-gnark-inputs ./prover.pkp ./proof.np
```

Recursively verify in a Gnark proof (reads the proof from `../ProveKit/prover/proof`):

```sh
cd ../../recursive-verifier
go run .
```

### Benchmarking

Benchmark against Barretenberg:

> _Note_: You can install Barretenberg from [here](https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/bbup/README.md).

> _Note_: You can install [hyperfine](https://github.com/sharkdp/hyperfine) using brew on OSX: `brew install hyperfine`.

```sh
cd noir-examples/poseidon-rounds
cargo run --release --bin provekit-cli prepare ./target/basic.json --pkp ./prover.pkp --pkv ./verifier.pkv
hyperfine 'nargo execute && bb prove -b ./target/basic.json -w ./target/basic.gz -o ./target' '../../target/release/provekit-cli prove ./prover.pkp ./Prover.toml'
```

### Profiling

#### Custom built-in profile (Memory usage)

The `provekit-cli` application has written custom memory profiler that prints basic info about memory usage when application
runs. To run binary with profiling enabled run it with cargo `--features profiling` param or compile with it.

```sh
cargo run --release --bin provekit-cli --features profiling prove ./prover.pkp ./Prover.toml -o ./proof.np
```

#### Using tracy (CPU and Memory usage)

Tracy tool [website](https://github.com/wolfpld/tracy). To install tracy tool on OSX use brew: `brew install tracy`.

> **Important**: integration is done with `Tracy Profiler 0.11.1`. It is newest version available from brew. Newer
> version may require updating dependencies as tracy is using its own protocol between app and tracy tool that changes
> with each major version.

TLDR; Tracy is an interactive tool to profile application. There is integration plugin for rust that works with
standard tracing annotation. For now it is integrated into `provekit-cli` binary only. Collecting profiling data requires
tracy to run during application profiling. You may noticed that it makes application to run much longer but mostly
due to data transfer between the application and the tracy running along.

Usage:

1. Start tracy from command line
```sh
tracy
```
2. Leave all fields with defaults and just click `Connect` button. It will cause tracy to start listening on the
   localhost for incoming data.
3.  Compile `noir-r1cs-profiled` binary.
```sh
cargo build --release --bin provekit-cli --features profiling
```
4. (OSX only) If you want to check call stacks additional command needs to be run (base on tracy instruction). The
   command must be run against each binary that is being profiled by tracy. This will create directory next to the 
   binary provided with `.dSYM` suffix (ex. `../../target/profiled-cli.dSYM`). Directory will contain the
   debug symbols and paths extracted with different format that is compatible with tracy tool. It must be rerun after
   each changes made to `provekit-cli` app.
```sh
 dsymutil ../../target/release/provekit-cli
```
5. Now start the application to profile:
```sh
../../target/release/provekit-cli prove ./prover.pkp ./Prover.toml -o ./proof.np
```
6. Go back to tracy tool. You should see that it receives data. App is interactive.

#### Using samply (CPU usage)

Samply tool [website](https://github.com/mstange/samply/) with instructions to install. It will start local server and
open a webpage with interactive app to view results. This does not require to run binary
with profiling enabled.

```sh
samply record -r 10000 -- ./../../target/release/provekit-cli prove ./prover.pkp ./Prover.toml -o ./proof.np
```

#### Using instruments (Memory usage) - OSX only

Cargo instruments tool [website](https://crates.io/crates/cargo-instruments) with instructions to install. It will open
results using built-in Instruments app. Results are interactive.

```sh
cargo instruments --template Allocations --release --bin provekit-cli prove ./prover.pkp ./Prover.toml -o ./proof.np
```

Samply tool [website](https://github.com/mstange/samply/) with instructions to install. It will start local server and
open a webpage with interactive app to view results. This does not require to run binary
with profiling enabled.

```sh
samply record -r 10000 -- ./../../target/release/provekit-cli prove ./prover.pkp ./Prover.toml -o ./proof.np
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
