use {
    crate::{
        gpa::{calculate_adr, gpa_sumcheck_verifier, run_gpa},
        types::{Memory, SPARKWHIRConfigs, SparkMatrix},
    },
    anyhow::{ensure, Result},
    ark_ff::{Fp, MontBackend},
    ark_std::One,
    itertools::izip,
    provekit_common::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperSponge},
        spark::SparkStatement,
        utils::{next_power_of_two, sumcheck::calculate_eq},
        FieldElement, WhirConfig,
    },
    spongefish::{codecs::arkworks_algebra::UnitToField, ProverState, VerifierState},
    whir::{
        crypto::fields::BN254Config,
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{reader::ParsedCommitment, Witness},
            prover::Prover,
            statement::{Statement, Weights},
            utils::{HintDeserialize, HintSerialize},
            verifier::Verifier,
        },
    },
};

/// Configuration bundle for row/column axis-specific data.
///
/// This zero-cost abstraction eliminates code duplication between
/// row-wise and column-wise memory checking protocols.
struct AxisConfig<'a> {
    eq_memory:       &'a [FieldElement],
    final_timestamp: &'a [FieldElement],
    read_timestamp:  &'a [FieldElement],
    address:         &'a [FieldElement],
    whir_config:     &'a WhirConfig,
}

/// Proves memory consistency for a single axis (row or column).
///
/// Executes two GPAs:
/// 1. Init-Final GPA: Proves memory state transitions from initialization to
///    final
/// 2. Read-Write GPA: Proves read-set and write-set timestamps are consistent
///
/// This is the core of SPARK's memory checking, ensuring that claimed memory
/// values match the actual constraint system evaluations.
#[inline]
fn prove_axis(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    config: AxisConfig<'_>,
    e_values: &[FieldElement],
    whir_configs: &SPARKWHIRConfigs,
    final_ts_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    axis_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    let mut tau_and_gamma = [FieldElement::from(0); 2];
    merlin.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    // Construct opening vectors for init/final GPA using Fiat-Shamir challenges.
    // Each opening encodes (address, value, timestamp) as: a*γ² + v*γ + t - τ
    let init_vec: Vec<_> = izip!(0.., config.eq_memory.iter(), config.final_timestamp.iter())
        .map(|(i, &v, _)| {
            let a = FieldElement::from(i);
            a * gamma * gamma + v * gamma - tau
        })
        .collect();

    let final_vec: Vec<_> = izip!(0.., config.eq_memory.iter(), config.final_timestamp.iter())
        .map(|(i, &v, &t)| {
            let a = FieldElement::from(i);
            a * gamma * gamma + v * gamma + t - tau
        })
        .collect();

    let gpa_randomness = run_gpa(merlin, &init_vec, &final_vec);
    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(1);

    let final_ts_eval = EvaluationsList::new(config.final_timestamp.to_vec())
        .evaluate(&MultilinearPoint(evaluation_randomness.to_vec()));
    merlin.hint(&final_ts_eval)?;

    produce_whir_proof(
        merlin,
        MultilinearPoint(evaluation_randomness.to_vec()),
        final_ts_eval,
        config.whir_config.clone(),
        final_ts_witness,
    )?;

    // RS WS GPA
    let rs_vec: Vec<_> = izip!(
        config.address.iter(),
        e_values.iter(),
        config.read_timestamp.iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + t - tau)
    .collect();

    let ws_vec: Vec<_> = izip!(
        config.address.iter(),
        e_values.iter(),
        config.read_timestamp.iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + (t + FieldElement::from(1)) - tau)
    .collect();

    let gpa_randomness = run_gpa(merlin, &rs_vec, &ws_vec);
    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(1);

    let eval_point = MultilinearPoint(evaluation_randomness.to_vec());

    let rs_address_eval = EvaluationsList::new(config.address.to_vec()).evaluate(&eval_point);
    merlin.hint(&rs_address_eval)?;

    let rs_value_eval = EvaluationsList::new(e_values.to_vec()).evaluate(&eval_point);
    merlin.hint(&rs_value_eval)?;

    let rs_timestamp_eval =
        EvaluationsList::new(config.read_timestamp.to_vec()).evaluate(&eval_point);
    merlin.hint(&rs_timestamp_eval)?;

    let br = axis_witness.batching_randomness;
    let claimed_eval = rs_address_eval + rs_value_eval * br + rs_timestamp_eval * br * br;

    assert_eq!(
        claimed_eval,
        axis_witness.batched_poly().evaluate(&eval_point)
    );

    produce_whir_proof(
        merlin,
        eval_point,
        claimed_eval,
        whir_configs.num_terms_3batched.clone(),
        axis_witness,
    )?;

    Ok(())
}

/// Proves row-wise memory consistency for the SPARK protocol.
///
/// # Arguments
/// * `merlin` - Prover's transcript state
/// * `matrix` - The preprocessed SPARK matrix with COO format and timestamps
/// * `memory` - Pre-computed equality check evaluations
/// * `e_rx` - Row evaluation vector
/// * `whir_configs` - WHIR polynomial commitment configurations
/// * `final_row_ts_witness` - Commitment witness for final row timestamps
/// * `rowwise_witness` - Batched commitment witness for row data
pub fn prove_rowwise(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    matrix: &SparkMatrix,
    memory: &Memory,
    e_rx: &[FieldElement],
    whir_configs: &SPARKWHIRConfigs,
    final_row_ts_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    rowwise_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    prove_axis(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_rx,
            final_timestamp: &matrix.timestamps.final_row,
            read_timestamp:  &matrix.timestamps.read_row,
            address:         &matrix.coo.row,
            whir_config:     &whir_configs.row,
        },
        e_rx,
        whir_configs,
        final_row_ts_witness,
        rowwise_witness,
    )
}

pub fn prove_colwise(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    matrix: &SparkMatrix,
    memory: &Memory,
    e_ry: &[FieldElement],
    whir_configs: &SPARKWHIRConfigs,
    final_col_ts_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    colwise_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    prove_axis(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_ry,
            final_timestamp: &matrix.timestamps.final_col,
            read_timestamp:  &matrix.timestamps.read_col,
            address:         &matrix.coo.col,
            whir_config:     &whir_configs.col,
        },
        e_ry,
        whir_configs,
        final_col_ts_witness,
        colwise_witness,
    )
}

// ============================================================================
// Verifier - Generic Implementation
// ============================================================================

#[inline]
fn verify_axis(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    num_axis_items: usize,
    num_nonzero_terms: usize,
    whir_config: &WhirConfig,
    num_terms_3batched_config: &WhirConfig,
    axis_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    init_mem_fn: impl Fn(&[FieldElement]) -> FieldElement,
) -> Result<()> {
    let mut tau_and_gamma = [FieldElement::from(0); 2];
    arthur.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    // Init Final GPA
    let gpa_result = gpa_sumcheck_verifier(
        arthur,
        provekit_common::utils::next_power_of_two(num_axis_items) + 2,
    )?;

    let claimed_init = gpa_result.claimed_values[0];
    let claimed_final = gpa_result.claimed_values[1];
    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let init_adr = calculate_adr(&evaluation_randomness.to_vec());
    let init_mem = init_mem_fn(&evaluation_randomness.to_vec());
    let init_opening = init_adr * gamma * gamma + init_mem * gamma - tau;

    let final_cntr: FieldElement = arthur.hint()?;

    let mut final_cntr_statement =
        Statement::<FieldElement>::new(provekit_common::utils::next_power_of_two(num_axis_items));
    final_cntr_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        final_cntr,
    );

    let final_cntr_verifier = Verifier::new(whir_config);
    final_cntr_verifier.verify(arthur, &finalts_commitment, &final_cntr_statement)?;

    let final_adr = calculate_adr(&evaluation_randomness.to_vec());
    let final_mem = init_mem_fn(&evaluation_randomness.to_vec());
    let final_opening = final_adr * gamma * gamma + final_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    // RS WS GPA
    let gpa_result = gpa_sumcheck_verifier(arthur, next_power_of_two(num_nonzero_terms) + 2)?;

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);
    let claimed_rs = gpa_result.claimed_values[0];
    let claimed_ws = gpa_result.claimed_values[1];

    let rs_adr: FieldElement = arthur.hint()?;
    let rs_mem: FieldElement = arthur.hint()?;
    let rs_timestamp: FieldElement = arthur.hint()?;

    let rs_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp - tau;
    let ws_opening =
        rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp + FieldElement::from(1) - tau;

    let evaluated_value =
        rs_opening * (FieldElement::one() - last_randomness[0]) + ws_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    let mut statement = Statement::<FieldElement>::new(provekit_common::utils::next_power_of_two(
        num_nonzero_terms,
    ));

    let br = axis_commitment.batching_randomness;
    statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec())),
        rs_adr + rs_mem * br + rs_timestamp * br * br,
    );

    let verifier = Verifier::new(num_terms_3batched_config);
    verifier.verify(arthur, &axis_commitment, &statement)?;

    ensure!(claimed_init * claimed_ws == claimed_rs * claimed_final);

    Ok(())
}

// ============================================================================
// Public API - Verifier
// ============================================================================

pub fn verify_rowwise(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    num_rows: usize,
    num_nonzero_terms: usize,
    whir_params: &SPARKWHIRConfigs,
    request: &SparkStatement,
    rowwise_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    row_finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
) -> Result<()> {
    verify_axis(
        arthur,
        num_rows,
        num_nonzero_terms,
        &whir_params.row,
        &whir_params.num_terms_3batched,
        rowwise_commitment,
        row_finalts_commitment,
        |eval_rand| calculate_eq(&request.point_to_evaluate.row, eval_rand),
    )
}

pub fn verify_colwise(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    num_cols: usize,
    num_nonzero_terms: usize,
    whir_params: &SPARKWHIRConfigs,
    request: &SparkStatement,
    colwise_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    col_finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
) -> Result<()> {
    verify_axis(
        arthur,
        num_cols,
        num_nonzero_terms,
        &whir_params.col,
        &whir_params.num_terms_3batched,
        colwise_commitment,
        col_finalts_commitment,
        |eval_rand| {
            calculate_eq(&request.point_to_evaluate.col[1..], eval_rand)
                * (FieldElement::from(1) - request.point_to_evaluate.col[0])
        },
    )
}

/// Helper to generate and verify a WHIR proof at a specific evaluation point.
///
/// # Note
/// This is called multiple times during SPARK proving for different polynomial
/// commitments.
fn produce_whir_proof(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    evaluation_point: MultilinearPoint<FieldElement>,
    evaluated_value: FieldElement,
    config: WhirConfig,
    witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    let mut statement = Statement::<FieldElement>::new(evaluation_point.num_variables());
    statement.add_constraint(Weights::evaluation(evaluation_point), evaluated_value);

    let prover = Prover::new(config);
    prover.prove(merlin, statement, witness)?;

    Ok(())
}
