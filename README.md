# ProveKit

Zero-knowledge proof toolkit targeting mobile devices.

## Requirements

This project makes use of Noir's `nargo` to compile circuits and generate test artifacts. Make sure to walk through the [Quick Start](https://noir-lang.org/docs/getting_started/quick_start#noir) section to install the noir toolchain. Note that we require a specific version of the toolchain, so make sure to override the version with the following command.

```sh
noirup --version nightly-2025-05-28
```

## Demo instructions

> _NOTE:_ The example below is being run for single example `poseidon-rounds`. You can use different example to run same commands.

Compile the Noir circuit:

```sh
cd noir-examples/poseidon-rounds
nargo compile
```

Generate the Noir Proof Scheme:

```sh
cargo run --release --bin noir-r1cs prepare ./target/basic.json -o ./noir-proof-scheme.nps
```

Generate the Noir Proof using the input Toml:

```sh
cargo run --release --bin noir-r1cs prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
```

Verify the Noir Proof:

```sh
cargo run --release --bin noir-r1cs verify ./noir-proof-scheme.nps ./noir-proof.np
```

Generate inputs for Gnark circuit:

```sh
cargo run --release --bin noir-r1cs generate-gnark-inputs ./noir-proof-scheme.nps ./noir-proof.np
```

Recursively verify in a Gnark proof (reads the proof from `../ProveKit/prover/proof`):

```sh
cd ../../gnark-whir
go run .
```

### Benchmarking

Benchmark against Barretenberg:

> _Note_: You can install Barretenberg from [here](https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/bbup/README.md).

> _Note_: You can install [hyperfine](https://github.com/sharkdp/hyperfine) using brew on OSX: `brew install hyperfine`.

```sh
cd noir-examples/poseidon-rounds
cargo run --release --bin noir-r1cs prepare ./target/basic.json -o ./scheme.nps
hyperfine 'nargo execute && bb prove -b ./target/basic.json -w ./target/basic.gz -o ./target' '../../target/release/noir-r1cs prove ./scheme.nps ./Prover.toml'
```

### Profiling

#### Custom built-in profile (Memory usage)

The `noir-r1cs` application has written custom memory profiler that prints basic info about memory usage when application
runs. To run binary with profiling enabled use `noir-r1cs-profiled` as binary name.

```sh
cargo run --release --bin noir-r1cs-profiled prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
```

#### Using tracy (CPU and Memory usage)

Tracy tool [website](https://github.com/wolfpld/tracy). To install tracy tool on OSX use brew: `brew install tracy`.

> **Important**: integration is done with `Tracy Profiler 0.11.1`. It is newest version available from brew. Newer
> version may require updating dependencies as tracy is using its own protocol between app and tracy tool that changes
> with each major version.

TLDR; Tracy is an interactive tool to profile application. There is integration plugin for rust that works with
standard tracing annotation. For now it is integrated into `noir-r1cs` binary only. Collecting profiling data requires
tracy to run during application profiling. You may noticed that it makes application to run much longer but mostly
due to data transfer between the application and the tracy running along.

Usage:

1. Start tracy from command line
```sh
tracy
```
2. Leave all fields with defaults and just click `Connect` button. It will cause tracy to start listening on the
   localhost for incoming data.
3. Now start the application to profile:
```sh
cargo run --release --bin noir-r1cs-profiled prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
```
4. Go back to tracy tool. You should see that it receives data. App is interactive.

#### Using samply (CPU usage)

Samply tool [website](https://github.com/mstange/samply/) with instructions to install. It will start local server and
open a webpage with interactive app to view results. This does not require to run binary
with profiling enabled.

```sh
samply record -r 10000 -- ./../../target/release/noir-r1cs prove ./noir-proof-scheme.nps ./noir-examples/poseidon-rounds/Prover.toml -o ./noir-proof.np
```

#### Using instruments (Memory usage) - OSX only

Cargo instruments tool [website](https://crates.io/crates/cargo-instruments) with instructions to install. It will open
results using built-in Instruments app. Results are interactive.

```sh
cargo instruments --template Allocations --release --bin noir-r1cs prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
```

Samply tool [website](https://github.com/mstange/samply/) with instructions to install. It will start local server and
open a webpage with interactive app to view results. This does not require to run binary
with profiling enabled.

```sh
samply record -r 10000 -- ./../../target/release/noir-r1cs prove ./noir-proof-scheme.nps ./noir-examples/poseidon-rounds/Prover.toml -o ./noir-proof.np
```

## Components

## Dependencies

This project depends on the following libraries, which are developed in lockstep:

- [🌪️ WHIR](https://github.com/WizardOfMenlo/whir)
- [Spongefish](https://github.com/arkworks-rs/spongefish)
- [gnark-skyscraper](https://github.com/reilabs/gnark-skyscraper)
- [gnark-whir](./gnark-whir/README.md)
- [noir](https://github.com/noir-lang/noir)
