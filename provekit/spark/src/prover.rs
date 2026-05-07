use {
    crate::{
        gpa::run_gpa4,
        memory::{prove_axis_init_final_product, AxisConfig},
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
        spark::R1CSSparkQuery, utils::next_power_of_two, FieldElement, HashConfig,
        TranscriptSponge, WhirConfig, WhirR1CSProof,
    },
    rayon::{join, prelude::*},
    std::borrow::Cow,
    tracing::instrument,
    whir::{
        algebra::{linear_form::MultilinearExtension, multilinear_extend},
        engines::EngineId,
        parameters::ProtocolParameters,
        transcript::{DomainSeparator, ProverState, VerifierMessage},
    },
};

pub trait SPARKProver {
    fn prove(
        &self,
        spark_data: &SparkProverContext,
        request: &R1CSSparkQuery,
    ) -> Result<SPARKProof>;
}

pub struct SPARKScheme {
    pub whir_configs:      SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

pub fn new_whir_config_for_size(
    log_size: usize,
    batch_size: usize,
    hash_id: EngineId,
) -> WhirConfig {
    let nv = log_size.max(4);

    let whir_params = ProtocolParameters {
        unique_decoding: false,
        initial_folding_factor: 3,
        security_level: 128,
        pow_bits: 10,
        folding_factor: 3,
        starting_log_inv_rate: 2,
        batch_size,
        hash_id,
    };

    WhirConfig::new(1 << nv, &whir_params)
}

impl SPARKScheme {
    pub fn new_for_r1cs(r1cs: &provekit_common::R1CS, hash_config: HashConfig) -> Self {
        let num_rows = 2 * r1cs.num_constraints();
        let num_cols = 2 * r1cs.num_witnesses();
        let nonzero_terms =
            r1cs.a().iter().count() + r1cs.b().iter().count() + r1cs.c().iter().count();

        Self::new(num_rows, num_cols, nonzero_terms, hash_config)
    }

    pub fn new(
        num_rows: usize,
        num_cols: usize,
        nonzero_terms: usize,
        hash_config: HashConfig,
    ) -> Self {
        let padded_num_entries = 1 << next_power_of_two(nonzero_terms);
        let hash_id = hash_config.engine_id();

        let row_config = new_whir_config_for_size(next_power_of_two(num_rows), 1, hash_id);
        let col_config = new_whir_config_for_size(next_power_of_two(num_cols), 1, hash_id);
        let num_terms_2batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 2, hash_id);
        let num_terms_5batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 5, hash_id);

        Self {
            whir_configs:      SPARKWHIRConfigs {
                row:                row_config,
                col:                col_config,
                num_terms_2batched: num_terms_2batched_config,
                num_terms_5batched: num_terms_5batched_config,
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
        let padded_num_entries = spark_data.matrix.coo.val.len();

        let mut merlin = ProverState::new(
            &DomainSeparator::protocol(&self.whir_configs)
                .session(&spark_data.setup.transcript.narg_string)
                .instance(&request.hash_bytes()),
            TranscriptSponge::default(),
        );

        let r: FieldElement = merlin.verifier_message();
        ensure!(
            !(FieldElement::ONE + r).is_zero(),
            "SPARK RLC randomness must not equal -1 (would zero the denominator)"
        );

        let b1 = r / (FieldElement::ONE + r);
        let combined = request.claimed_a + r * request.claimed_b + r * r * request.claimed_c;
        let claimed_value =
            combined / (FieldElement::ONE + r) / (FieldElement::ONE + r);

        let (memory, e_values) = compute_spark_data(request, b1, spark_data, padded_num_entries);

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
    b1: FieldElement,
    spark_data: &SparkProverContext,
    padded_num_entries: usize,
) -> (Memory, EValuesForMatrix) {
    let memory = calculate_memory(
        b1,
        &request.point_to_evaluate.row,
        &request.point_to_evaluate.col,
    );
    let e_values = compute_e_values(spark_data, &memory, padded_num_entries);
    (memory, e_values)
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

    let (folding_randomness, sumcheck_final_folds) =
        sumcheck_and_its_proofs(merlin, &data.matrix, e_values, claimed_value)?;

    memory_checking(
        merlin,
        data,
        e_values,
        &e_values_witness,
        memory,
        whir_configs,
        &folding_randomness,
        sumcheck_final_folds,
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
    folding_randomness: &[FieldElement],
    sumcheck_final_folds: [FieldElement; 3],
) -> Result<()> {
    let tau: FieldElement = merlin.verifier_message();
    let gamma: FieldElement = merlin.verifier_message();
    let challenges = Challenges { tau, gamma };

    prove_combined_rs_ws_product(
        merlin,
        &data.matrix,
        e_values,
        e_values_witness,
        &data.witnesses.vals_rs_ws_witness,
        whir_configs,
        &challenges,
        folding_randomness,
        sumcheck_final_folds,
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
) -> Result<(Vec<FieldElement>, [FieldElement; 3])> {
    let mles: [&[FieldElement]; 3] = [&matrix.coo.val, &e_values.e_rx, &e_values.e_ry];
    let (sumcheck_final_folds, folding_randomness) =
        run_spark_sumcheck(merlin, mles, claimed_value)?;

    merlin.prover_hint_ark(&[
        sumcheck_final_folds[0],
        sumcheck_final_folds[1],
        sumcheck_final_folds[2],
    ]);

    Ok((folding_randomness, [
        sumcheck_final_folds[0],
        sumcheck_final_folds[1],
        sumcheck_final_folds[2],
    ]))
}

#[instrument(skip_all)]
fn prove_combined_rs_ws_product(
    merlin: &mut ProverState<TranscriptSponge>,
    matrix: &SparkMatrix,
    e_values: &EValuesForMatrix,
    e_values_witness: &WhirWitness,
    vals_rs_ws_witness: &WhirWitness,
    whir_configs: &SPARKWHIRConfigs,
    challenges: &Challenges,
    folding_randomness: &[FieldElement],
    sumcheck_final_folds: [FieldElement; 3],
) -> Result<()> {
    let gamma_sq = challenges.gamma * challenges.gamma;
    let one = FieldElement::from(1u64);

    let row_field = &matrix.coo.row_field;
    let col_field = &matrix.coo.col_field;
    let n = row_field.len();

    let gpa_leaves_flat = tracing::info_span!("build_rs_ws_pairs").in_scope(|| {
        let mut buf = vec![FieldElement::from(0u64); 4 * n];
        let (row_section, col_section) = buf.split_at_mut(2 * n);
        let (row_rs, row_ws) = row_section.split_at_mut(n);
        let (col_rs, col_ws) = col_section.split_at_mut(n);

        row_rs
            .par_iter_mut()
            .zip(row_ws.par_iter_mut())
            .zip(col_rs.par_iter_mut())
            .zip(col_ws.par_iter_mut())
            .enumerate()
            .for_each(|(i, (((rs_r, ws_r), rs_c), ws_c))| {
                let row_base = row_field[i] * gamma_sq
                    + e_values.e_rx[i] * challenges.gamma
                    + matrix.timestamps.read_row[i]
                    - challenges.tau;
                let col_base = col_field[i] * gamma_sq
                    + e_values.e_ry[i] * challenges.gamma
                    + matrix.timestamps.read_col[i]
                    - challenges.tau;
                *rs_r = row_base;
                *ws_r = row_base + one;
                *rs_c = col_base;
                *ws_c = col_base + one;
            });
        buf
    });
    let gpa_randomness = run_gpa4(merlin, gpa_leaves_flat)?;

    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(2);

    let polys: [&[FieldElement]; 4] = [
        row_field,
        &matrix.timestamps.read_row,
        col_field,
        &matrix.timestamps.read_col,
    ];
    let [row_address_eval, row_timestamp_eval, col_address_eval, col_timestamp_eval]: [_; 4] =
        tracing::info_span!("multilinear_extend_rs_ws")
            .in_scope(|| {
                polys
                    .par_iter()
                    .map(|p| multilinear_extend(p, evaluation_randomness))
                    .collect::<Vec<_>>()
            })
            .try_into()
            .expect("4 polys");

    merlin.prover_hint_ark(&row_address_eval);
    merlin.prover_hint_ark(&row_timestamp_eval);
    merlin.prover_hint_ark(&col_address_eval);
    merlin.prover_hint_ark(&col_timestamp_eval);

    let pairs: [(&[FieldElement], &[FieldElement]); 5] = [
        (row_field, folding_randomness),
        (&matrix.timestamps.read_row, folding_randomness),
        (col_field, folding_randomness),
        (&matrix.timestamps.read_col, folding_randomness),
        (&matrix.coo.val, evaluation_randomness),
    ];
    let [row_field_at_fold, read_row_at_fold, col_field_at_fold, read_col_at_fold, vals_at_eval]: [_; 5] =
        tracing::info_span!("multilinear_extend_vals_rs_ws_cross")
            .in_scope(|| {
                pairs
                    .par_iter()
                    .map(|(p, r)| multilinear_extend(p, r))
                    .collect::<Vec<_>>()
            })
            .try_into()
            .expect("5 polys");

    merlin.prover_hint_ark(&row_field_at_fold);
    merlin.prover_hint_ark(&read_row_at_fold);
    merlin.prover_hint_ark(&col_field_at_fold);
    merlin.prover_hint_ark(&read_col_at_fold);
    merlin.prover_hint_ark(&vals_at_eval);

    let fold_lf_for_vals_rs_ws = MultilinearExtension::new(folding_randomness.to_vec());
    let eval_lf_for_vals_rs_ws = MultilinearExtension::new(evaluation_randomness.to_vec());
    // Layout: linear_form-major, then poly. Polys: [vals, row_field, read_row,
    // col_field, read_col].
    let vals_rs_ws_evaluations = [
        // fold_lf
        sumcheck_final_folds[0],
        row_field_at_fold,
        read_row_at_fold,
        col_field_at_fold,
        read_col_at_fold,
        // eval_lf
        vals_at_eval,
        row_address_eval,
        row_timestamp_eval,
        col_address_eval,
        col_timestamp_eval,
    ];
    let _ = whir_configs.num_terms_5batched.prove(
        merlin,
        vec![
            Cow::Borrowed(&matrix.coo.val),
            Cow::Borrowed(row_field),
            Cow::Borrowed(&matrix.timestamps.read_row),
            Cow::Borrowed(col_field),
            Cow::Borrowed(&matrix.timestamps.read_col),
        ],
        vec![Cow::Borrowed(vals_rs_ws_witness)],
        vec![
            Box::new(fold_lf_for_vals_rs_ws)
                as Box<dyn whir::algebra::linear_form::LinearForm<FieldElement>>,
            Box::new(eval_lf_for_vals_rs_ws)
                as Box<dyn whir::algebra::linear_form::LinearForm<FieldElement>>,
        ],
        Cow::Borrowed(&vals_rs_ws_evaluations),
    );

    let (row_value_eval, col_value_eval) = tracing::info_span!("multilinear_extend_e_values")
        .in_scope(|| {
            join(
                || multilinear_extend(&e_values.e_rx, evaluation_randomness),
                || multilinear_extend(&e_values.e_ry, evaluation_randomness),
            )
        });
    merlin.prover_hint_ark(&row_value_eval);
    merlin.prover_hint_ark(&col_value_eval);

    let fold_lf = MultilinearExtension::new(folding_randomness.to_vec());
    let eval_lf = MultilinearExtension::new(evaluation_randomness.to_vec());
    let evaluations = [
        sumcheck_final_folds[1],
        sumcheck_final_folds[2],
        row_value_eval,
        col_value_eval,
    ];
    let _ = whir_configs.num_terms_2batched.prove(
        merlin,
        vec![Cow::Borrowed(&e_values.e_rx), Cow::Borrowed(&e_values.e_ry)],
        vec![Cow::Borrowed(e_values_witness)],
        vec![
            Box::new(fold_lf) as Box<dyn whir::algebra::linear_form::LinearForm<FieldElement>>,
            Box::new(eval_lf) as Box<dyn whir::algebra::linear_form::LinearForm<FieldElement>>,
        ],
        Cow::Borrowed(&evaluations),
    );

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
