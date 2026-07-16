# SPARK

Reference for this implementation
- SPARK: https://eprint.iacr.org/2019/550
- Stronger security analysis of SPARK: https://people.cs.georgetown.edu/jthaler/Lasso-paper.pdf

## Proposed prototype workflow
1. Provekit prepare step
    - Compiles the circuit and writes the prover/verifier artifacts (`.pkp`, `.pkv`).
    - With `--spark`, also runs SPARK preprocessing once: the SPARK setup is
      folded into the verifier key (`.pkv`) and the bundled SPARK prover
      context (matrix, witnesses, setup) is written to `.spctx`.

2. Provekit prove step
    - Runs the provekit prover and obtains the Noir proof plus the deferred
      matrix evaluations (SPARK queries).
    - Writes each query as `spark_query_<i>.json` to `--spark-queries-dir`.

3. Provekit prove-spark step
    - Reads the SPARK prover context (`--spctx`) produced in step 1 and the
      queries from `--spark-dir`, then produces a single batched SPARK proof
      (`spark_proof.sp` written back to the same directory). When the query
      set has more than one entry the prover RLC's them with a
      transcript-derived `beta` and runs a parallel sumcheck before falling
      into the single-query SPARK protocol; with one query it goes straight to
      that protocol.

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

The current implementation emits **two SPARK queries** for the dual-commitment
path — one per split half. Both queries are then batched into a single SPARK
proof by RLC'ing their per-matrix claims with a transcript-derived `beta` and
running one parallel sumcheck of `Σ_i β^i · eq(col_i, x) · M(α, x)` for
M ∈ {A, B, C}. The folded values become the claims of a single synthesized
query passed into the single-query SPARK protocol.


## Full workflow for the `range-check-u8` Noir passport circuit:

```bash
cargo build --release --bin provekit-cli

cd noir-examples/noir-r1cs-test-programs/range-check-u8
nargo compile


# 1. Prepare the circuit (compiles and writes prover/verifier artifacts; the
#    SPARK setup is folded into the .pkv, and the bundled SPARK prover context
#    is written to .spctx).
cargo run --release --bin provekit-cli -- prepare ./target/main.json \
  --pkp ./spark-artifacts/range-check-u8.pkp \
  --pkv ./spark-artifacts/range-check-u8.pkv \
  --spark \
  --spctx ./spark-artifacts/range-check-u8.spctx

# 2. Prove (generates Noir proof + writes SPARK queries to disk).
#    `--produce-spark-query` is required, otherwise no queries are written.
cargo run --release --bin provekit-cli -- prove \
  -p ./spark-artifacts/range-check-u8.pkp \
  -i ./Prover.toml \
  -o ./spark-artifacts/range-check-u8-proof.np \
  --spark-queries-dir ./spark_proofs \
  --produce-spark-query

# 3. Generate one batched SPARK proof covering every query written in step 2.
#    The prover reads the `spark_queries.json` batch in --spark-dir plus the
#    SPARK prover context from --spctx, and writes a single
#    ./spark_proofs/spark_proof.sp.
cargo run --release --bin provekit-cli -- prove-spark ./spark-artifacts/range-check-u8.pkp \
  --spark-dir ./spark_proofs \
  --spctx ./spark-artifacts/range-check-u8.spctx

# 4. Natively verify the Noir proof. Native verification evaluates MLE directly. Spark proofs are useful only in the recursive verifier.
cargo run --release --bin provekit-cli -- verify \
  -v ./spark-artifacts/range-check-u8.pkv \
  --proof ./spark-artifacts/range-check-u8-proof.np

# 5. Verify the batched SPARK proof. The verifier pulls the SPARK setup from
#    the trusted .pkv. The transcript instance is bound to the serialized query
#    batch, so its contents and order must match the batch used by prove-spark.
cargo run --release --bin provekit-cli -- verify-spark \
  ./spark_proofs/spark_proof.sp \
  ./spark-artifacts/range-check-u8.pkv \
  ./spark_proofs/spark_queries.json

# TODO: 6. Recursively verify the Noir proof and SPARK.
```

The `range-check-u8` circuit uses the multi-challenge Noir API, so the
provekit prover takes the dual-commitment path and emits **two** spark
queries (`spark_query_0.json` and `spark_query_1.json`). Single-commitment
circuits emit just `spark_query_0.json` and step 5 needs only that one path.
