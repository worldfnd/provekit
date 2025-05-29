## How to run

### Clone the `gnark-whir` repo and checkout the branch
```bash
git clone git@github.com:reilabs/gnark-whir.git
```
```bash
cd gnark-whir
```
```bash
git checkout adjust-to-current-provekit
```

### Clone the `ProveKit` repo and download the correct version of Noir

```bash
cd ..
```
```bash
git clone https://github.com/worldfnd/ProveKit
```
```bash
cd ProveKit
```
```bash
noirup -C 03b58fa2
```
### Generate the outputs from poseidon-rounds example
```bash
cd noir-examples/poseidon-rounds
```
```bash
nargo compile
```
```bash
nargo execute
```
```bash
cargo run --release --bin noir-r1cs prepare ./target/basic.json -o ./noir-proof-scheme.nps
```
```bash
cargo run --release --bin noir-r1cs prove ./noir-proof-scheme.nps ./target/basic.gz -o ./noir-proof.np
```
```bash
cargo run --release --bin noir-r1cs generate-gnark-inputs ./noir-proof-scheme.nps ./noir-proof.np
```
### Run `gnark-whir`
```bash
cd ../../../gnark-whir
```
```bash
go run .
```