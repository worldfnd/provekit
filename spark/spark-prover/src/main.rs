use {
    anyhow::{Context, Result},
    spark_prover::utilities::deserialize_r1cs,
};

fn main() -> Result<()> {
    let r1cs = deserialize_r1cs("spark/spark-prover/r1cs.json")
        .context("Error: Failed to create R1CS object")?;
    Ok(())
}
