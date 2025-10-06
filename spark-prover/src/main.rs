use {
    anyhow::{Context, Result},
    argh::FromArgs,
    ark_ff::AdditiveGroup,
    provekit_common::{
        gnark::WHIRConfigGnark,
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern},
        FieldElement, IOPattern, WhirR1CSScheme,
    },
    provekit_r1cs_compiler::WhirR1CSSchemeBuilder,
    spark_prover::utilities::{
        deserialize_r1cs, deserialize_request,
        iopattern::SPARKDomainSeparator,
        matrix::{COOMatrix, SparkMatrix, TimeStamps},
        memory::{calculate_memory, EValuesForMatrix},
        spark::prove_spark_for_single_matrix,
        whir::SPARKWHIRConfigsNew,
        MatrixDimensionsNew, SPARKProof, SPARKProofGnarkNew,
    },
    spongefish::codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    std::{collections::BTreeMap, fs::File, io::Write, path::PathBuf},
    whir::whir::{domainsep::WhirDomainSeparator, utils::HintSerialize},
};

#[derive(FromArgs)]
#[argh(description = "Spark Prover CLI")]
struct Args {
    /// r1cs
    #[argh(option)]
    r1cs: PathBuf,

    /// request
    #[argh(option)]
    request: PathBuf,
}
fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let r1cs = deserialize_r1cs(&args.r1cs).context("Error: Failed to create the R1CS object")?;

    // get combined matrix non-zero value coordinates

    let mut combined_matrix_map: BTreeMap<(usize, usize), FieldElement> = r1cs
        .a()
        .iter()
        .map(|(coordinate, _)| (coordinate, FieldElement::ZERO))
        .collect();
    for (coordinate, _) in r1cs.b().iter() {
        combined_matrix_map
            .entry(coordinate)
            .or_insert(FieldElement::ZERO);
    }
    for (coordinate, _) in r1cs.c().iter() {
        combined_matrix_map
            .entry(coordinate)
            .or_insert(FieldElement::ZERO);
    }

    // generate padded row and col

    let originial_num_entries = combined_matrix_map.keys().count();
    let padded_num_entries = 1 << next_power_of_two(combined_matrix_map.keys().count());

    let mut row = Vec::with_capacity(padded_num_entries);
    let mut col = Vec::with_capacity(padded_num_entries);

    for (r, c) in combined_matrix_map.keys() {
        row.push(FieldElement::from(*r as u64));
        col.push(FieldElement::from(*c as u64));
    }

    let to_fill = padded_num_entries - originial_num_entries;
    row.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));
    col.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));

    // generate val vectors

    let mut val_a = vec![FieldElement::ZERO; padded_num_entries];
    let mut val_b = vec![FieldElement::ZERO; padded_num_entries];
    let mut val_c = vec![FieldElement::ZERO; padded_num_entries];

    let a_binding = r1cs.a();
    let b_binding = r1cs.b();
    let c_binding = r1cs.c();

    let mut a_iter = a_binding.iter();
    let mut b_iter = b_binding.iter();
    let mut c_iter = c_binding.iter();

    let mut a_cur = a_iter.next();
    let mut b_cur = b_iter.next();
    let mut c_cur = c_iter.next();

    for (index, coordinate) in combined_matrix_map.keys().enumerate() {
        if let Some((coord, value)) = a_cur {
            if coord == *coordinate {
                val_a[index] = value;
                a_cur = a_iter.next();
            }
        }

        if let Some((coord, value)) = b_cur {
            if coord == *coordinate {
                val_b[index] = value;
                b_cur = b_iter.next();
            }
        }

        if let Some((coord, value)) = c_cur {
            if coord == *coordinate {
                val_c[index] = value;
                c_cur = c_iter.next();
            }
        }
    }

    // generate padded timestamps

    let mut read_row_counters = vec![0; r1cs.num_constraints()];
    let mut read_col_counters = vec![0; r1cs.num_witnesses()];
    let mut read_row = Vec::with_capacity(padded_num_entries);
    let mut read_col = Vec::with_capacity(padded_num_entries);

    for (r, c) in combined_matrix_map.keys() {
        read_row.push(FieldElement::from(read_row_counters[*r] as u64));
        read_col.push(FieldElement::from(read_col_counters[*c] as u64));
        read_row_counters[*r] += 1;
        read_col_counters[*c] += 1;
    }

    for _ in 0..to_fill {
        read_row.push(FieldElement::from(read_row_counters[0] as u64));
        read_col.push(FieldElement::from(read_col_counters[0] as u64));
        read_row_counters[0] += 1;
        read_col_counters[0] += 1;
    }

    let final_row = read_row_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect::<Vec<_>>();

    let final_col = read_col_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect::<Vec<_>>();

    // Run for each request
    let request = deserialize_request(&args.request)
        .context("Error: Failed to deserialize the request object")?;

    let memory = calculate_memory(request.point_to_evaluate.clone());

    let mut e_rx = Vec::with_capacity(padded_num_entries);
    let mut e_ry = Vec::with_capacity(padded_num_entries);

    for (r, c) in combined_matrix_map.keys() {
        e_rx.push(memory.eq_rx[*r]);
        e_ry.push(memory.eq_ry[*c]);
    }

    e_rx.extend(std::iter::repeat(memory.eq_rx[0]).take(to_fill));
    e_ry.extend(std::iter::repeat(memory.eq_ry[0]).take(to_fill));

    // Create whir config

    let row_config =
        WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(r1cs.num_constraints()), 1);
    let col_config =
        WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(r1cs.num_witnesses()), 1);
    let num_terms_3batched_config =
        WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(padded_num_entries), 3);
    let num_terms_5batched_config =
        WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(padded_num_entries), 5);

    // Create io_pattern
    let mut io = IOPattern::new("💥");

    // Matrix A
    io = io
        .hint("point_row")
        .hint("point_col")
        .add_claimed_evaluations();

    io = io
        .commit_statement(&num_terms_5batched_config)
        .commit_statement(&num_terms_3batched_config)
        .commit_statement(&num_terms_3batched_config)
        .commit_statement(&row_config)
        .commit_statement(&col_config)
        .add_sumcheck_polynomials(next_power_of_two(padded_num_entries))
        .hint("sumcheck_last_folds")
        .add_whir_proof(&num_terms_5batched_config);

    // Rowwise

    io = io.add_tau_and_gamma();

    for i in 0..=next_power_of_two(r1cs.num_constraints()) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    io = io
        .hint("row_final_counter_claimed_evaluation")
        .add_whir_proof(&row_config);

    for i in 0..=next_power_of_two(padded_num_entries) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    io = io
        .hint("row_rs_address_claimed_evaluation")
        .hint("row_rs_value_claimed_evaluation")
        .hint("row_rs_timestamp_claimed_evaluation")
        .add_whir_proof(&num_terms_3batched_config);

    // Colwise

    io = io.add_tau_and_gamma();

    for i in 0..=next_power_of_two(r1cs.num_witnesses()) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    io = io
        .hint("col_final_counter_claimed_evaluation")
        .add_whir_proof(&col_config);

    for i in 0..=next_power_of_two(padded_num_entries) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    io = io
        .hint("col_rs_address_claimed_evaluation")
        .hint("col_rs_value_claimed_evaluation")
        .hint("col_rs_timestamp_claimed_evaluation")
        .add_whir_proof(&num_terms_3batched_config);

    // Prover

    let mut merlin = io.to_prover_state();

    merlin.hint(&request.point_to_evaluate.row)?;
    merlin.hint(&request.point_to_evaluate.col)?;

    // Calculate the RLC of the matrices
    // Note: can be also calculated from rlc of val_a, val_b, val_c
    merlin.add_scalars(&[
        request.claimed_values.a,
        request.claimed_values.b,
        request.claimed_values.c,
    ])?;
    let mut matrix_batching_randomness = [FieldElement::ZERO; 1];
    merlin.fill_challenge_scalars(&mut matrix_batching_randomness)?;
    let matrix_batching_randomness = matrix_batching_randomness[0];
    let matrix_batching_randomness_sq = matrix_batching_randomness * matrix_batching_randomness;

    for (coordinate, value) in r1cs.a().iter() {
        combined_matrix_map
            .entry(coordinate)
            .and_modify(|cur| *cur += value);
    }

    for (coordinate, value) in r1cs.b().iter() {
        combined_matrix_map
            .entry(coordinate)
            .and_modify(|cur| *cur += value * matrix_batching_randomness);
    }

    for (coordinate, value) in r1cs.c().iter() {
        combined_matrix_map
            .entry(coordinate)
            .and_modify(|cur| *cur += value * matrix_batching_randomness_sq);
    }

    let mut val = Vec::with_capacity(padded_num_entries);
    for value in combined_matrix_map.values() {
        val.push(*value);
    }
    val.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));

    let claimed_value = request.claimed_values.a
        + request.claimed_values.b * matrix_batching_randomness
        + request.claimed_values.c * matrix_batching_randomness_sq;

    //

    let spark_matrix = SparkMatrix {
        coo:        COOMatrix {
            row,
            col,
            val,
            val_a,
            val_b,
            val_c,
        },
        timestamps: TimeStamps {
            read_row,
            read_col,
            final_row,
            final_col,
        },
    };

    let e_values = EValuesForMatrix { e_rx, e_ry };

    let configs = SPARKWHIRConfigsNew {
        row:                row_config,
        col:                col_config,
        num_terms_3batched: num_terms_3batched_config,
        num_terms_5batched: num_terms_5batched_config,
    };

    prove_spark_for_single_matrix(
        &mut merlin,
        spark_matrix,
        &memory,
        e_values,
        claimed_value,
        &configs,
    )?;

    let spark_proof = SPARKProof {
        transcript:        merlin.narg_string().to_vec(),
        io_pattern:        String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        whir_params:       configs,
        matrix_dimensions: MatrixDimensionsNew {
            num_rows:      r1cs.num_constraints(),
            num_cols:      r1cs.num_witnesses(),
            nonzero_terms: originial_num_entries,
        },
    };

    let mut spark_proof_file = File::create("spark-prover/spark_proof.json")
        .context("Error: Failed to create the spark proof file")?;

    spark_proof_file
        .write_all(serde_json::to_string(&spark_proof).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");

    let spark_proof_gnark = SPARKProofGnarkNew {
        transcript:    spark_proof.transcript,
        io_pattern:    spark_proof.io_pattern,
        whir_row:      WHIRConfigGnark::new(&spark_proof.whir_params.row),
        whir_col:      WHIRConfigGnark::new(&spark_proof.whir_params.col),
        whir_3batched: WHIRConfigGnark::new(&spark_proof.whir_params.num_terms_3batched),
        whir_5batched: WHIRConfigGnark::new(&spark_proof.whir_params.num_terms_5batched),
        log_num_terms: next_power_of_two(padded_num_entries),
    };

    let mut gnark_spark_proof_file = File::create("spark-prover/gnark_spark_proof.json")
        .context("Error: Failed to create the spark proof file")?;

    gnark_spark_proof_file
        .write_all(
            serde_json::to_string(&spark_proof_gnark)
                .unwrap()
                .as_bytes(),
        )
        .expect("Writing spark gnark parameters to a file failed");

    Ok(())
}
