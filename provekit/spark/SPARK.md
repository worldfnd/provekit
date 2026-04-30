# SPARK

Reference for this implementation
- SPARK: https://eprint.iacr.org/2019/550
- Stronger security analysis of SPARK: https://people.cs.georgetown.edu/jthaler/Lasso-paper.pdf

## Proposed prototype workflow
1. Provekit prepare step
    - Compiles the circuit and writes the prover/verifier artifacts (`.pkp`, `.pkv`).
    - With `--spark`, also runs SPARK preprocessing once and writes the SPARK
      setup transcript (`.spc`).

2. Provekit prove step
    - Runs the provekit prover and obtains the Noir proof plus the deferred
      matrix evaluations (SPARK queries).
    - Writes each query as `spark_query_<i>.json` to `--spark-queries-dir`.

3. Provekit prove-spark step
    - Reads queries from `--spark-dir` and produces a SPARK proof per query
      (`spark_proof_<i>.sp` written back to the same directory).

4. Provekit and SPARK verify step
    - Verifies Provekit and SPARK proofs

## Design decisions

### Pack $A$, $B$, $C$ into one block matrix Z:
This is a result from Marcin (https://gist.github.com/kustosz/14b62de666f721ab855536e575891bd1)

**The trick:** 

$$Z = \begin{bmatrix} A & B \\ 0 & C \end{bmatrix}$$

Same total non-zeros, double the dimensions. Then for any $\beta$, $p$, and $q$:

$$A(p,q) + \beta B(p,q) + \beta^2 C(p,q) = (1+\beta)^2 \cdot Z\!\left(\tfrac{\beta}{1+\beta}, p,\ \tfrac{\beta}{1+\beta}, q\right)$$

One matrix, one commitment, one opening.

### Batching GPA and WHIR proofs

- Combining GPA
  - Products of hashes corresponding to read sets and write sets of row-wise and column-wise memory check are combined into one GPA
  - Products of hashes corresponding to init and final vectors are combined into one GPA (separate for row-wise and col-wise memory). Possible optimization - if number of rows and columns for the matrix are ensured to be equal, we can combine them into one GPA.

- WHIR Batching
| `num_terms_2batched` e-values are committed and opened together. Opened once in sumcheck and once in rs_ws GPA
| `num_terms_4batched` | Address/timestamp values for row-wise and col-wise memory checks are committed and opened together

### Split witness: two SPARK queries 
The current ZK WHIR doesn't support batching which would enable easier handling of split witness commitment. 

The current implementation emits **two SPARK
queries** for the dual-commitment path — one per split half.


## Full workflow for a Noir passport circuit:

```bash
cargo build --release --bin provekit-cli

cd noir-examples/power
nargo compile

# 1. Prepare the circuit (compiles and writes prover/verifier artifacts plus
#    the SPARK setup transcript).
cargo run --release --bin provekit-cli -- prepare ./target/power.json \
  --pkp ./benchmark-inputs/power.pkp \
  --pkv ./benchmark-inputs/power.pkv \
  --spark \
  --spc ./benchmark-inputs/power.spc

# 2. Prove (generates Noir proof + writes SPARK queries to disk).
cargo run --release --bin provekit-cli -- prove ./benchmark-inputs/power.pkp ./Prover.toml \
  -o ./benchmark-inputs/power-proof.np \
  --spark-queries-dir ./spark_proofs

# 3. Generate SPARK proofs for the queries written in step 2.
cargo run --release --bin provekit-cli -- prove-spark ./benchmark-inputs/power.pkp \
  --spark-dir ./spark_proofs

# 4. Natively verify the Noir proof. Native verification evaluates MLE directly. Spark proofs are useful only in the recursive verifier.
cargo run --release --bin provekit-cli -- verify ./benchmark-inputs/power.pkv ./benchmark-inputs/power-proof.np

# 5. Verify a standalone SPARK proof. Needs the per-proof artifacts (.sp, .json)
#    plus the SPARK setup transcript (.spc) emitted by `prepare --spark`.
cargo run --release --bin provekit-cli -- verify-spark ./spark_proofs/spark_proof_0.sp ./benchmark-inputs/power.spc ./spark_proofs/spark_query_0.json

# TODO: 6. Recursively verify the Noir proof and SPARK.
```