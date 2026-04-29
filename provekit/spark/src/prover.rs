use {
    crate::{
        gpa::run_gpa4,
        memory::{produce_whir_proof, prove_axis_init_final_product, AxisConfig},
        sumcheck::run_spark_sumcheck,
        types::{
            Challenges, EValuesForMatrix, MatrixDimensions, Memory, SPARKProof, SPARKWHIRConfigs,
            SparkMatrix, SparkProverContext, WhirWitness,
        },
        utils::calculate_memory,
    },
    anyhow::{ensure, Result},
    ark_ff::{Field, Zero},
    provekit_common::{
        spark::R1CSSparkQuery, utils::next_power_of_two, FieldElement, WhirR1CSProof,
        TranscriptSponge, WhirConfig,
    },
    rayon::{join, prelude::*},
    tracing::instrument,
    whir::{
        algebra::multilinear_extend,
        parameters::ProtocolParameters,
        transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierMessage},
    },
};

pub trait SPARKProver {
    fn prove(&self, spark_data: &SparkProverContext, request: &R1CSSparkQuery)
        -> Result<SPARKProof>;
}

pub struct SPARKScheme {
    pub whir_configs:      SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

pub fn new_whir_config_for_size(log_size: usize, batch_size: usize) -> WhirConfig {
    let nv = log_size.max(4);

    let whir_params = ProtocolParameters {
        unique_decoding: false,
        initial_folding_factor: 3,
        security_level: 128,
        pow_bits: 10,
        folding_factor: 3,
        starting_log_inv_rate: 2,
        batch_size,
        hash_id: whir::hash::SHA2,
    };

    WhirConfig::new(1 << nv, &whir_params)
}

impl SPARKScheme {
    pub fn new_for_r1cs(r1cs: &provekit_common::R1CS) -> Self {
        let num_rows = 2 * r1cs.num_constraints();
        let num_cols = 2 * r1cs.num_witnesses();
        let nonzero_terms =
            r1cs.a().iter().count() + r1cs.b().iter().count() + r1cs.c().iter().count();

        Self::new(num_rows, num_cols, nonzero_terms)
    }

    pub fn new(num_rows: usize, num_cols: usize, nonzero_terms: usize) -> Self {
        let padded_num_entries = 1 << next_power_of_two(nonzero_terms);

        let row_config = new_whir_config_for_size(next_power_of_two(num_rows), 1);
        let col_config = new_whir_config_for_size(next_power_of_two(num_cols), 1);
        let num_terms_1batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 1);
        let num_terms_2batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 2);
        let num_terms_4batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 4);

        Self {
            whir_configs:      SPARKWHIRConfigs {
                row:                row_config,
                col:                col_config,
                num_terms_1batched: num_terms_1batched_config,
                num_terms_2batched: num_terms_2batched_config,
                num_terms_4batched: num_terms_4batched_config,
            },
            matrix_dimensions: MatrixDimensions {
                num_rows,
                num_cols,
                nonzero_terms,
            },
        }
    }
}

impl SPARKProver for SPARKScheme {
    #[instrument(skip_all)]
    fn prove(
        &self,
        spark_data: &SparkProverContext,
        request: &R1CSSparkQuery,
    ) -> Result<SPARKProof> {
        ensure!(
            !(FieldElement::ONE + request.matrix_batching_randomness).is_zero(),
            "matrix_batching_randomness must not equal -1 (would zero the SPARK denominator)"
        );

        let padded_num_entries = spark_data.matrix.coo.val.len();

        let ds = DomainSeparator::protocol(&self.whir_configs)
            .session(&spark_data.setup.transcript.narg_string)
            .instance(&Empty);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::default());

        let (memory, e_values) = compute_spark_data(request, spark_data, padded_num_entries);

        let claimed_value = (request.claimed_value
            / (FieldElement::ONE + request.matrix_batching_randomness))
            / (FieldElement::ONE + request.matrix_batching_randomness);

        prove_spark(
            &mut merlin,
            spark_data,
            &e_values,
            claimed_value,
            &memory,
            &self.whir_configs,
        )?;

        let proof = merlin.proof();
        Ok(SPARKProof(WhirR1CSProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        }))
    }
}

#[instrument(skip_all)]
fn compute_spark_data(
    request: &R1CSSparkQuery,
    spark_data: &SparkProverContext,
    padded_num_entries: usize,
) -> (Memory, EValuesForMatrix) {
    let memory = compute_memory(request);
    let e_values = compute_e_values(spark_data, &memory, padded_num_entries);
    (memory, e_values)
}

#[instrument(skip_all)]
fn compute_memory(request: &R1CSSparkQuery) -> Memory {
    calculate_memory(
        request.matrix_batching_randomness
            / (FieldElement::ONE + request.matrix_batching_randomness),
        &request.point_to_evaluate.row,
        &request.point_to_evaluate.col,
    )
}

#[instrument(skip_all)]
fn compute_e_values(
    spark_data: &SparkProverContext,
    memory: &Memory,
    padded_num_entries: usize,
) -> EValuesForMatrix {
    let (e_rx, e_ry) = rayon::join(
        || {
            spark_data.matrix.coo.row[..padded_num_entries]
                .par_iter()
                .map(|&r| memory.eq_rx[r])
                .collect()
        },
        || {
            spark_data.matrix.coo.col[..padded_num_entries]
                .par_iter()
                .map(|&c| memory.eq_ry[c])
                .collect()
        },
    );
    EValuesForMatrix { e_rx, e_ry }
}

#[instrument(skip_all)]
fn prove_spark(
    merlin: &mut ProverState<TranscriptSponge>,
    data: &SparkProverContext,
    e_values: &EValuesForMatrix,
    claimed_value: FieldElement,
    memory: &Memory,
    whir_configs: &SPARKWHIRConfigs,
) -> Result<()> {
    let e_values_witness = commit_e_values(merlin, whir_configs, e_values);

    sumcheck_and_its_proofs(
        merlin,
        &data.matrix,
        e_values,
        claimed_value,
        &e_values_witness,
        &data.witnesses.vals_witness,
        whir_configs,
    )?;

    memory_checking(
        merlin,
        data,
        e_values,
        &e_values_witness,
        memory,
        whir_configs,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn memory_checking(
    merlin: &mut ProverState<TranscriptSponge>,
    data: &SparkProverContext,
    e_values: &EValuesForMatrix,
    e_values_witness: &WhirWitness,
    memory: &Memory,
    whir_configs: &SPARKWHIRConfigs,
) -> Result<()> {
    let tau: FieldElement = merlin.verifier_message();
    let gamma: FieldElement = merlin.verifier_message();
    let challenges = Challenges { tau, gamma };

    prove_combined_rs_ws_product(
        merlin,
        &data.matrix,
        e_values,
        e_values_witness,
        &data.witnesses.rs_ws_witness,
        whir_configs,
        &challenges,
    )?;

    prove_axis_init_final_product(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_rx,
            final_timestamp: &data.matrix.timestamps.final_row,
            whir_config:     &whir_configs.row,
        },
        &data.witnesses.final_row_ts_witness,
        &challenges,
    )?;

    prove_axis_init_final_product(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_ry,
            final_timestamp: &data.matrix.timestamps.final_col,
            whir_config:     &whir_configs.col,
        },
        &data.witnesses.final_col_ts_witness,
        &challenges,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn sumcheck_and_its_proofs(
    merlin: &mut ProverState<TranscriptSponge>,
    matrix: &SparkMatrix,
    e_values: &EValuesForMatrix,
    claimed_value: FieldElement,
    e_values_witness: &WhirWitness,
    vals_witness: &WhirWitness,
    whir_configs: &SPARKWHIRConfigs,
) -> Result<()> {
    let mles: [&[FieldElement]; 3] = [&matrix.coo.val, &e_values.e_rx, &e_values.e_ry];
    let (sumcheck_final_folds, folding_randomness) =
        run_spark_sumcheck(merlin, mles, claimed_value)?;

    merlin.prover_hint_ark(&[
        sumcheck_final_folds[0],
        sumcheck_final_folds[1],
        sumcheck_final_folds[2],
    ]);

    produce_whir_proof(
        merlin,
        &folding_randomness,
        &[&e_values.e_rx, &e_values.e_ry],
        &whir_configs.num_terms_2batched,
        e_values_witness,
    )?;

    produce_whir_proof(
        merlin,
        &folding_randomness,
        &[&matrix.coo.val],
        &whir_configs.num_terms_1batched,
        vals_witness,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn prove_combined_rs_ws_product(
    merlin: &mut ProverState<TranscriptSponge>,
    matrix: &SparkMatrix,
    e_values: &EValuesForMatrix,
    e_values_witness: &WhirWitness,
    rs_ws_witness: &WhirWitness,
    whir_configs: &SPARKWHIRConfigs,
    challenges: &Challenges,
) -> Result<()> {
    let gamma_sq = challenges.gamma * challenges.gamma;
    let one = FieldElement::from(1u64);

    let row_field = &matrix.coo.row_field;
    let col_field = &matrix.coo.col_field;
    let n = row_field.len();
    let m = col_field.len();

    let (row_pairs, col_pairs) = tracing::info_span!("build_rs_ws_pairs").in_scope(|| {
        join(
            || {
                (0..n)
                    .into_par_iter()
                    .map(|i| {
                        let a = row_field[i];
                        let v = e_values.e_rx[i];
                        let t = matrix.timestamps.read_row[i];
                        let base = a * gamma_sq + v * challenges.gamma + t - challenges.tau;
                        (base, base + one)
                    })
                    .collect::<Vec<(FieldElement, FieldElement)>>()
            },
            || {
                (0..m)
                    .into_par_iter()
                    .map(|i| {
                        let a = col_field[i];
                        let v = e_values.e_ry[i];
                        let t = matrix.timestamps.read_col[i];
                        let base = a * gamma_sq + v * challenges.gamma + t - challenges.tau;
                        (base, base + one)
                    })
                    .collect::<Vec<(FieldElement, FieldElement)>>()
            },
        )
    });
    let (row_rs_vec, row_ws_vec): (Vec<_>, Vec<_>) = row_pairs.into_iter().unzip();
    let (col_rs_vec, col_ws_vec): (Vec<_>, Vec<_>) = col_pairs.into_iter().unzip();

    let mut gpa_leaves_flat = Vec::with_capacity(4 * row_rs_vec.len());
    let gpa_leaves = [row_rs_vec, row_ws_vec, col_rs_vec, col_ws_vec];
    gpa_leaves_flat.extend(gpa_leaves.into_iter().flatten());
    let gpa_randomness = run_gpa4(merlin, gpa_leaves_flat)?;

    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(2);

    let ((row_address_eval, row_timestamp_eval), (col_address_eval, col_timestamp_eval)) =
        tracing::info_span!("multilinear_extend_rs_ws").in_scope(|| {
            join(
                || {
                    join(
                        || multilinear_extend(row_field, evaluation_randomness),
                        || multilinear_extend(&matrix.timestamps.read_row, evaluation_randomness),
                    )
                },
                || {
                    join(
                        || multilinear_extend(col_field, evaluation_randomness),
                        || multilinear_extend(&matrix.timestamps.read_col, evaluation_randomness),
                    )
                },
            )
        });

    merlin.prover_hint_ark(&row_address_eval);
    merlin.prover_hint_ark(&row_timestamp_eval);
    merlin.prover_hint_ark(&col_address_eval);
    merlin.prover_hint_ark(&col_timestamp_eval);

    let rs_ws_vecs: [&[FieldElement]; 4] = [
        &matrix.coo.row_field,
        &matrix.timestamps.read_row,
        &matrix.coo.col_field,
        &matrix.timestamps.read_col,
    ];

    produce_whir_proof(
        merlin,
        evaluation_randomness,
        &rs_ws_vecs,
        &whir_configs.num_terms_4batched,
        rs_ws_witness,
    )?;

    let (row_value_eval, col_value_eval) = tracing::info_span!("multilinear_extend_e_values")
        .in_scope(|| {
            join(
                || multilinear_extend(&e_values.e_rx, evaluation_randomness),
                || multilinear_extend(&e_values.e_ry, evaluation_randomness),
            )
        });
    merlin.prover_hint_ark(&row_value_eval);
    merlin.prover_hint_ark(&col_value_eval);

    produce_whir_proof(
        merlin,
        evaluation_randomness,
        &[&e_values.e_rx, &e_values.e_ry],
        &whir_configs.num_terms_2batched,
        e_values_witness,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn commit_e_values(
    merlin: &mut ProverState<TranscriptSponge>,
    whir_configs: &SPARKWHIRConfigs,
    e_values: &EValuesForMatrix,
) -> WhirWitness {
    whir_configs
        .num_terms_2batched
        .commit(merlin, &[&e_values.e_rx, &e_values.e_ry])
}
