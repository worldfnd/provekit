use {
    anyhow::{Context, Result},
    spark_prover::utilities::{
        create_io_pattern, deserialize_r1cs, deserialize_request, get_spark_r1cs,
    },
};

fn main() -> Result<()> {
    // Run once when receiving the matrix
    let r1cs = deserialize_r1cs("spark/spark-prover/r1cs.json")
        .context("Error: Failed to create the R1CS object")?;
    let spark_r1cs = get_spark_r1cs(r1cs);
    // Run for each request
    let request = deserialize_request("spark/spark-prover/request.json")
        .context("Error: Failed to create the request object")?;
    let mut merlin = create_io_pattern().to_prover_state();
    Ok(())
}
