use {
    crate::{
        gpa::run_gpa4,
        memory::{produce_whir_proof, prove_colwise, prove_rowwise},
        sumcheck::run_spark_sumcheck,
        types::{
            EValuesForMatrix, MatrixDimensions, Memory, SPARKProof, SPARKWHIRConfigs,
            SerializableCommitment, SparkCommitments, SparkMatrix, SparkPreparedData,
            SparkWitnesses, WhirWitness,
        },
        utils::calculate_memory,
    },
    anyhow::Result,
    ark_ff::Field,
    provekit_common::{
        spark::R1CSSparkQuery, utils::next_power_of_two, FieldElement, TranscriptSponge, WhirConfig,
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
    fn prove(&self, spark_data: SparkPreparedData, request: &R1CSSparkQuery) -> Result<SPARKProof>;
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
    fn prove(&self, spark_data: SparkPreparedData, request: &R1CSSparkQuery) -> Result<SPARKProof> {
        let spark_matrix: SparkMatrix = spark_data.matrix.into();
        let spark_witnesses: SparkWitnesses = spark_data.witnesses.into();
        let commitments = spark_data.commitments;
        let padded_num_entries = spark_matrix.coo.val.len();

        let ds = DomainSeparator::protocol(&self.whir_configs).instance(&Empty);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::default());

        let memory = calculate_memory(
            request.matrix_batching_randomness
                / (FieldElement::ONE + request.matrix_batching_randomness),
            request.point_to_evaluate.row.clone(),
            request.point_to_evaluate.col.clone(),
        );

        let claimed_value = (request.claimed_value
            / (FieldElement::ONE + request.matrix_batching_randomness))
            / (FieldElement::ONE + request.matrix_batching_randomness);

        let mut e_rx = Vec::with_capacity(padded_num_entries);
        let mut e_ry = Vec::with_capacity(padded_num_entries);

        for i in 0..padded_num_entries {
            let r = spark_matrix.coo.row[i];
            let c = spark_matrix.coo.col[i];
            debug_assert!(
                r < memory.eq_rx.len(),
                "COO row index {r} out of bounds (len {})",
                memory.eq_rx.len()
            );
            debug_assert!(
                c < memory.eq_ry.len(),
                "COO col index {c} out of bounds (len {})",
                memory.eq_ry.len()
            );
            e_rx.push(memory.eq_rx[r]);
            e_ry.push(memory.eq_ry[c]);
        }

        let row_field: Vec<FieldElement> = spark_matrix
            .coo
            .row
            .iter()
            .map(|&r| FieldElement::from(r as u64))
            .collect();
        let col_field: Vec<FieldElement> = spark_matrix
            .coo
            .col
            .iter()
            .map(|&c| FieldElement::from(c as u64))
            .collect();

        let e_values = EValuesForMatrix { e_rx, e_ry };

        prove_spark_for_single_matrix(
            &mut merlin,
            &spark_matrix,
            row_field,
            col_field,
            &memory,
            e_values,
            claimed_value,
            &self.whir_configs,
            spark_witnesses,
            commitments,
        )?;

        let proof = merlin.proof();
        Ok(SPARKProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
            whir_params: self.whir_configs.clone(),
            matrix_dimensions: self.matrix_dimensions.clone(),
        })
    }
}

#[instrument(skip_all)]
fn prove_spark_for_single_matrix(
    merlin: &mut ProverState<TranscriptSponge>,
    matrix: &SparkMatrix,
    row_field: Vec<FieldElement>,
    col_field: Vec<FieldElement>,
    memory: &Memory,
    e_values: EValuesForMatrix,
    claimed_value: FieldElement,
    whir_configs: &SPARKWHIRConfigs,
    spark_witnesses: SparkWitnesses,
    commitments: SparkCommitments,
) -> Result<()> {
    replay_commitment(merlin, &commitments.vals, &whir_configs.num_terms_1batched);
    replay_commitment(merlin, &commitments.rs_ws, &whir_configs.num_terms_4batched);
    replay_commitment(merlin, &commitments.final_row_ts, &whir_configs.row);
    replay_commitment(merlin, &commitments.final_col_ts, &whir_configs.col);

    let GeneratedWitnesses {
        evalues_witness,
        evalues_vecs,
    } = generate_witnesses(merlin, whir_configs, &e_values)?;

    let rs_ws_vecs = [
        row_field.to_vec(),
        matrix.timestamps.read_row.clone(),
        col_field.to_vec(),
        matrix.timestamps.read_col.clone(),
    ];

    spark_sumcheck(
        merlin,
        &matrix.coo.val,
        &e_values.e_rx,
        &e_values.e_ry,
        &claimed_value,
        &evalues_vecs,
        &evalues_witness,
        &matrix.coo.val,
        spark_witnesses.vals_witness,
        &whir_configs.num_terms_1batched,
        &whir_configs.num_terms_2batched,
    )?;

    let tau: FieldElement = merlin.verifier_message();
    let gamma: FieldElement = merlin.verifier_message();

    run_rs_ws_gpa_and_proofs(
        merlin,
        &matrix,
        &row_field,
        &col_field,
        &e_values,
        spark_witnesses.rs_ws_witness,
        rs_ws_vecs,
        evalues_witness,
        evalues_vecs,
        whir_configs,
        &gamma,
        &tau,
    )?;

    prove_rowwise(
        merlin,
        &matrix.timestamps.final_row,
        memory,
        whir_configs,
        spark_witnesses.final_row_ts_witness,
        &gamma,
        &tau,
    )?;

    prove_colwise(
        merlin,
        &matrix.timestamps.final_col,
        memory,
        whir_configs,
        spark_witnesses.final_col_ts_witness,
        &gamma,
        &tau,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn spark_sumcheck(
    merlin: &mut ProverState<TranscriptSponge>,
    val: &[FieldElement],
    e_rx: &[FieldElement],
    e_ry: &[FieldElement],
    claimed_value: &FieldElement,
    evalues_vecs: &[Vec<FieldElement>; 2],
    evalues_witness: &WhirWitness,
    vals_vec: &[FieldElement],
    vals_witness: WhirWitness,
    num_terms_1batched: &WhirConfig,
    num_terms_2batched: &WhirConfig,
) -> Result<()> {
    let mles: [&[FieldElement]; 3] = [val, e_rx, e_ry];
    let (sumcheck_final_folds, folding_randomness) =
        run_spark_sumcheck(merlin, mles, *claimed_value)?;

    merlin.prover_hint_ark(&[
        sumcheck_final_folds[0],
        sumcheck_final_folds[1],
        sumcheck_final_folds[2],
    ]);

    produce_whir_proof(
        merlin,
        &folding_randomness,
        &[evalues_vecs[0].as_slice(), evalues_vecs[1].as_slice()],
        num_terms_2batched,
        evalues_witness.clone(),
    )?;

    produce_whir_proof(
        merlin,
        &folding_randomness,
        &[vals_vec],
        num_terms_1batched,
        vals_witness,
    )?;

    Ok(())
}

#[instrument(skip_all)]
fn run_rs_ws_gpa_and_proofs(
    merlin: &mut ProverState<TranscriptSponge>,
    matrix: &SparkMatrix,
    row_field: &[FieldElement],
    col_field: &[FieldElement],
    e_values: &EValuesForMatrix,
    rs_ws_witness: WhirWitness,
    rs_ws_vecs: [Vec<FieldElement>; 4],
    evalues_witness: WhirWitness,
    evalues_vecs: [Vec<FieldElement>; 2],
    whir_configs: &SPARKWHIRConfigs,
    gamma: &FieldElement,
    tau: &FieldElement,
) -> Result<()> {
    let gamma_sq = *gamma * *gamma;
    let one = FieldElement::from(1u64);

    let n = row_field.len();
    let m = col_field.len();

    let (row_pairs, col_pairs) = join(
        || {
            (0..n)
                .into_par_iter()
                .map(|i| {
                    let a = row_field[i];
                    let v = e_values.e_rx[i];
                    let t = matrix.timestamps.read_row[i];
                    let base = a * gamma_sq + v * *gamma + t - *tau;
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
                    let base = a * gamma_sq + v * *gamma + t - *tau;
                    (base, base + one)
                })
                .collect::<Vec<(FieldElement, FieldElement)>>()
        },
    );
    let (row_rs_vec, row_ws_vec): (Vec<_>, Vec<_>) = row_pairs.into_iter().unzip();
    let (col_rs_vec, col_ws_vec): (Vec<_>, Vec<_>) = col_pairs.into_iter().unzip();

    let mut gpa_leaves_flat = Vec::with_capacity(4 * row_rs_vec.len());
    let gpa_leaves = [row_rs_vec, row_ws_vec, col_rs_vec, col_ws_vec];
    gpa_leaves_flat.extend(gpa_leaves.into_iter().flatten());
    let gpa_randomness = run_gpa4(merlin, gpa_leaves_flat)?;

    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(2);

    let ((row_address_eval, row_timestamp_eval), (col_address_eval, col_timestamp_eval)) = join(
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
    );

    merlin.prover_hint_ark(&row_address_eval);
    merlin.prover_hint_ark(&row_timestamp_eval);
    merlin.prover_hint_ark(&col_address_eval);
    merlin.prover_hint_ark(&col_timestamp_eval);

    produce_whir_proof(
        merlin,
        evaluation_randomness,
        &[
            rs_ws_vecs[0].as_slice(),
            rs_ws_vecs[1].as_slice(),
            rs_ws_vecs[2].as_slice(),
            rs_ws_vecs[3].as_slice(),
        ],
        &whir_configs.num_terms_4batched,
        rs_ws_witness,
    )?;

    let (row_value_eval, col_value_eval) = join(
        || multilinear_extend(&e_values.e_rx, evaluation_randomness),
        || multilinear_extend(&e_values.e_ry, evaluation_randomness),
    );
    merlin.prover_hint_ark(&row_value_eval);
    merlin.prover_hint_ark(&col_value_eval);

    produce_whir_proof(
        merlin,
        evaluation_randomness,
        &[evalues_vecs[0].as_slice(), evalues_vecs[1].as_slice()],
        &whir_configs.num_terms_2batched,
        evalues_witness,
    )?;

    Ok(())
}

struct GeneratedWitnesses {
    evalues_witness: WhirWitness,
    evalues_vecs:    [Vec<FieldElement>; 2],
}

#[instrument(skip_all)]
fn generate_witnesses(
    merlin: &mut ProverState<TranscriptSponge>,
    whir_configs: &SPARKWHIRConfigs,
    e_values: &EValuesForMatrix,
) -> Result<GeneratedWitnesses> {
    let evalues_vecs = [e_values.e_rx.clone(), e_values.e_ry.clone()];
    let evalues_witness = whir_configs.num_terms_2batched.commit(merlin, &[
        evalues_vecs[0].as_slice(),
        evalues_vecs[1].as_slice(),
    ]);

    Ok(GeneratedWitnesses {
        evalues_witness,
        evalues_vecs,
    })
}

fn replay_commitment(
    merlin: &mut ProverState<TranscriptSponge>,
    commitment: &SerializableCommitment,
    config: &WhirConfig,
) {
    let ic = &config.initial_committer;

    // Absorb the Merkle root
    merlin.prover_message(&commitment.merkle_root);

    // Draw OOD challenge points (deterministic from transcript state)
    let _oods_points: Vec<FieldElement> = merlin.verifier_message_vec(ic.out_domain_samples);

    // Absorb OOD evaluations
    for eval in &commitment.out_of_domain_evals {
        merlin.prover_message(eval);
    }
}
