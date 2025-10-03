# SPARK 
Experimental Rust prover and gnark recursive prover circuit will be implemented and optimized here.

## Running 
```
noirup --version v1.0.0-beta.11
cd noir-examples/noir-passport-examples/complete_age_check
nargo compile
cargo run --release --bin provekit-cli prepare ./target/complete_age_check.json -o ./noir-proof-scheme.nps
cargo run --release --bin provekit-cli prove ./noir-proof-scheme.nps ./Prover.toml -o ./noir-proof.np
cargo run --release --bin provekit-cli generate-gnark-inputs ./noir-proof-scheme.nps ./noir-proof.np
cd ../../.. 
cargo run --bin spark-prover -- --r1cs "noir-examples/noir-passport-examples/complete_age_check/r1cs.json" --request "noir-examples/noir-passport-examples/complete_age_check/spark_request.json"
cargo run -p spark-prover --bin spark-verifier -- --proof "spark-prover/spark_proof.json" --request "noir-examples/noir-passport-examples/complete_age_check/spark_request.json"
cd recursive-verifier/cmd/cli
go run . --config "../../../noir-examples/noir-passport-examples/complete_age_check/params_for_recursive_verifier" --r1cs "../../../noir-examples/noir-passport-examples/complete_age_check/r1cs.json" --evaluation spark --spark_config "../../../spark-prover/gnark_spark_proof.json" 
```

## Running SPARK (under development)
```cargo run --bin spark-prover```

## Test R1CS generation (for development)
A development utility is provided to generate test matrices.
To generate a test R1CS, run the following command:

```cargo run -p spark-prover --bin generate_test_r1cs```

## Test request generation (for development)
A development utility is provided to generate test requests.
To generate a test request, run the following command:

```cargo run -p spark-prover --bin generate_test_request```

## Reference SPARK verifier (for development)
A reference SPARK verifier is implemented to test the correctness of the SPARK proof while being a reference implementation for the gnark verifier circuit.

```cargo run -p spark-prover --bin spark-verifier```