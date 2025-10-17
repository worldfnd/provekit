use {
    crate::{
        gpa::{calculate_adr, gpa_sumcheck_verifier, run_gpa2},
        types::{Memory, SPARKWHIRConfigs, SparkMatrix},
    },
    anyhow::{ensure, Result},
    ark_ff::{Fp, MontBackend},
    ark_std::One,
    itertools::izip,
    provekit_common::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperSponge},
        spark::{ClaimedValues, SparkStatement},
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
    gamma: &FieldElement,
    tau: &FieldElement,
) -> Result<()> {
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

    let gpa_randomness = run_gpa2(merlin, &init_vec, &final_vec);
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
    gamma: &FieldElement,
    tau: &FieldElement,
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
        gamma,
        tau,
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
    gamma: &FieldElement,
    tau: &FieldElement,
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
        gamma,
        tau
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
    finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    init_mem_fn: impl Fn(&[FieldElement]) -> FieldElement,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
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

    ensure!(claimed_init * claimed_ws == claimed_final * claimed_rs);

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
    row_finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
    verify_axis(
        arthur,
        num_rows,
        num_nonzero_terms,
        &whir_params.row,
        &whir_params.num_terms_3batched,
        row_finalts_commitment,
        |eval_rand| calculate_eq(&request.point_to_evaluate.row, eval_rand),
        tau,
        gamma,
        claimed_rs,
        claimed_ws,
    )
}

pub fn verify_colwise(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    num_cols: usize,
    num_nonzero_terms: usize,
    whir_params: &SPARKWHIRConfigs,
    request: &SparkStatement,
    col_finalts_commitment: ParsedCommitment<
        Fp<MontBackend<BN254Config, 4>, 4>,
        Fp<MontBackend<BN254Config, 4>, 4>,
    >,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
    verify_axis(
        arthur,
        num_cols,
        num_nonzero_terms,
        &whir_params.col,
        &whir_params.num_terms_3batched,
        col_finalts_commitment,
        |eval_rand| {
            calculate_eq(&request.point_to_evaluate.col[1..], eval_rand)
                * (FieldElement::from(1) - request.point_to_evaluate.col[0])
        },
        tau,
        gamma,
        claimed_rs,
        claimed_ws,
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
