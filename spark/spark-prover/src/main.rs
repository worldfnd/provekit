use {
    anyhow::{Context, Result},
    spark_prover::{
        memory::{calculate_e_values_for_r1cs, calculate_memory},
        spark::prove_spark_for_single_matrix,
        utilities::{create_io_pattern, deserialize_r1cs, deserialize_request, get_spark_r1cs},
    },
};

fn main() -> Result<()> {
    // Run once when receiving the matrix
    let r1cs = deserialize_r1cs("spark/spark-prover/r1cs.json")
        .context("Error: Failed to create the R1CS object")?;
    let spark_r1cs = get_spark_r1cs(&r1cs);

    // Run for each request
    let request = deserialize_request("spark/spark-prover/request.json")
        .context("Error: Failed to create the request object")?;
    let memory = calculate_memory(request.point_to_evaluate);
    let e_values = calculate_e_values_for_r1cs(&memory, &r1cs);
    let mut merlin = create_io_pattern(&r1cs).to_prover_state();

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_r1cs.a,
        memory,
        e_values.a,
        request.claimed_values.a,
    )?;

    Ok(())
}
