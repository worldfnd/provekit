use {
    anyhow::{Context, Result},
    provekit_common::{file::write, utils::next_power_of_two, gnark::WHIRConfigGnark},
    spark_prover::{
        memory::{calculate_e_values_for_r1cs, calculate_memory},
        spark::prove_spark_for_single_matrix,
        utilities::{
            calculate_matrix_dimensions, create_io_pattern, deserialize_r1cs, deserialize_request,
            get_spark_r1cs, SPARKProof, SPARKProofGnark,
        },
        whir::create_whir_configs,
    },
    std::{fs::File, io::Write, mem},
};

fn main() -> Result<()> {
    // Run once when receiving the matrix
    let r1cs = deserialize_r1cs("spark-prover/r1cs.json")
        .context("Error: Failed to create the R1CS object")?;
    let spark_r1cs = get_spark_r1cs(&r1cs);
    let spark_whir_configs = create_whir_configs(&r1cs);

    // Run for each request
    let request = deserialize_request("spark-prover/request.json")
        .context("Error: Failed to deserialize the request object")?;

    let memory = calculate_memory(request.point_to_evaluate);
    let e_values = calculate_e_values_for_r1cs(&memory, &r1cs);
    let io_pattern = create_io_pattern(&r1cs, &spark_whir_configs);
    let mut merlin = io_pattern.to_prover_state();

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_r1cs.a,
        &memory,
        e_values.a,
        request.claimed_values.a,
        &spark_whir_configs,
        &spark_whir_configs.a_3batched,
    )?;

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_r1cs.b,
        &memory,
        e_values.b,
        request.claimed_values.b,
        &spark_whir_configs,
        &spark_whir_configs.b_3batched,
    )?;

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_r1cs.c,
        &memory,
        e_values.c,
        request.claimed_values.c,
        &spark_whir_configs,
        &spark_whir_configs.c_3batched,
    )?;

    let spark_proof = SPARKProof {
        transcript:        merlin.narg_string().to_vec(),
        io_pattern:        String::from_utf8(io_pattern.as_bytes().to_vec()).unwrap(),
        whir_params:       spark_whir_configs,
        matrix_dimensions: calculate_matrix_dimensions(&r1cs),
    };

    let mut spark_proof_file = File::create("spark-prover/spark_proof.json")
        .context("Error: Failed to create the spark proof file")?;

    spark_proof_file
        .write_all(serde_json::to_string(&spark_proof).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");

    println!("Claimed value for A {:?}", request.claimed_values.a); //Reilabs Debug: 

    let spark_proof_gnark = SPARKProofGnark {
        transcript: spark_proof.transcript,
        io_pattern: spark_proof.io_pattern,
        whir_row: WHIRConfigGnark::new(&spark_proof.whir_params.row),
        whir_col: WHIRConfigGnark::new(&spark_proof.whir_params.col),
        whir_a3: WHIRConfigGnark::new(&spark_proof.whir_params.a_3batched),
        log_a_num_terms: next_power_of_two(r1cs.a.num_entries()),
        claimed_value_for_a: request.claimed_values.a,
    };

    let mut gnark_spark_proof_file = File::create("spark-prover/gnark_spark_proof.json")
        .context("Error: Failed to create the spark proof file")?;

    gnark_spark_proof_file
        .write_all(serde_json::to_string(&spark_proof_gnark).unwrap().as_bytes())
        .expect("Writing spark gnark parameters to a file failed");

    // println!("{:?}", request.claimed_values.a);
    // println!("{:?}", request.claimed_values.b);
    // println!("{:?}", request.claimed_values.c);

    Ok(())
}
