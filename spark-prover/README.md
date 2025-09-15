# SPARK 
Experimental Rust prover and gnark recursive prover circuit will be implemented and optimized here.

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