use {
    anyhow::{Context, Result},
    noir_r1cs::utils::next_power_of_two,
    spark_prover::{
        memory::{calculate_e_values_for_r1cs, calculate_memory},
        spark::prove_spark_for_single_matrix,
        utilities::{create_io_pattern, deserialize_r1cs, deserialize_request, get_spark_r1cs, SPARKProof},
        whir::create_whir_configs,
    },
    std::{fs::File, io::Write},
};

fn main() -> Result<()> {
    // Run once when receiving the matrix
    let r1cs = deserialize_r1cs("spark/spark-prover/r1cs.json")
        .context("Error: Failed to create the R1CS object")?;
    let spark_r1cs = get_spark_r1cs(&r1cs);
    let spark_whir_configs = create_whir_configs(&r1cs);
    // Run for each request
    let request = deserialize_request("spark/spark-prover/request.json")
        .context("Error: Failed to create the request object")?;
    let memory = calculate_memory(request.point_to_evaluate);
    let e_values = calculate_e_values_for_r1cs(&memory, &r1cs);
    let io_pattern = create_io_pattern(&r1cs, &spark_whir_configs);
    let mut merlin = io_pattern.to_prover_state();

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_r1cs.a,
        memory,
        e_values.a,
        request.claimed_values.a,
        &spark_whir_configs,
    )?;

    let spark_proof = SPARKProof {
        transcript: merlin.narg_string().to_vec(),
        io_pattern: String::from_utf8(io_pattern.as_bytes().to_vec()).unwrap(),
    };

    let mut spark_proof_file = File::create("spark/spark-prover/spark_proof")
        .context("Error: Failed to create the spark proof file")?;
    spark_proof_file
        .write_all(serde_json::to_string(&spark_proof).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");

    Ok(())
}
