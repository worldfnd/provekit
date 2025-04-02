# ProveKit

Zero-knowledge proof toolkit targeting mobile devices.

## Demo instructions

First make sure you have the exact correct version of Noir installed [so the artifacts can be read](./Cargo.toml#L58):

```sh
noirup -C 03b58fa2
```

Compile the Noir circuit:

```sh
cd noir-r1cs/noir-examples/poseidon-rounds
nargo compile
```

Generate the Noir Proof Scheme:

```sh
cargo run --release --bin noir-r1cs prepare ./noir-examples/poseidon-rounds/target/basic.json --output-path ./noir_proof_scheme.bin
```

(Currently this doesn't write an output file)

Generate the Noir Proof using the input Toml:

```sh
cargo run --release --bin noir-r1cs prove ./noir-examples/poseidon-rounds/target/basic.json ./noir-examples/poseidon-rounds/Prover.toml
```

Recursively verify in a Gnark proof (reads the proof from `../ProveKit/prover/proof`):

```sh
cd ..
git clone https://github.com/reilabs/gnark-whir
cd gnark-whir
go run .
```

## Components

## Dependencies

This project depends on the following libraries, which are developed in lockstep:

- [🌪️ WHIR](https://github.com/WizardOfMenlo/whir)
- [Spongefish](https://github.com/arkworks-rs/spongefish)
- [gnark-skyscraper](https://github.com/reilabs/gnark-skyscraper)
- [gnark-nimue](https://github.com/reilabs/gnark-nimue)
- [gnark-whir](https://github.com/reilabs/gnark-whir)
- [noir](https://github.com/noir-lang/noir)
