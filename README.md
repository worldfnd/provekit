# ProveKit

Zero-knowledge proof toolkit targeting mobile devices.

## Demo instructions

First make sure you have the exact correct version of Noir installed [so the artifacts can be read](./Cargo.toml#L58):

```sh
noirup -C 03b58fa2
```

Compile the Noir circuit and generate the witness:

```sh
cd noir-r1cs/noir-examples/poseidon-rounds
nargo execute
```

Generate the R1CS instance:

```sh
cargo run --release --bin noir-r1cs ./noir-r1cs/noir-examples/poseidon-rounds/target/basic.json ./noir-r1cs/noir-examples/poseidon-rounds/target/basic.gz
```

Generate the WHIR GR1CS proof:

```sh
cargo run --release --bin prover -- --input_file_path ./noir-r1cs/r1cs.json
```

This will write the proof to `prover/proof`.

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
