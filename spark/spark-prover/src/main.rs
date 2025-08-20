use {
    anyhow::{Context, Result},
    spark_prover::utilities::{create_io_pattern, deserialize_r1cs, get_spark_r1cs},
};

fn main() -> Result<()> {
    let r1cs = deserialize_r1cs("spark/spark-prover/r1cs.json")
        .context("Error: Failed to create R1CS object")?;
    let spark_r1cs = get_spark_r1cs(r1cs);
    let mut merlin = create_io_pattern().to_prover_state();
    Ok(())
}
