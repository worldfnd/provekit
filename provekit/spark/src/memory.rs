use {
    crate::{
        gpa::{calculate_adr, gpa_sumcheck_verifier2, run_gpa2},
        types::{Memory, SPARKWHIRConfigs, WhirWitness},
    },
    anyhow::{ensure, Result},
    ark_std::One,
    rayon::prelude::*,
    provekit_common::{
        spark::R1CSSparkQuery, utils::sumcheck::calculate_eq, FieldElement, TranscriptSponge,
        WhirConfig,
    },
    std::borrow::Cow,
    tracing::instrument,
    whir::{
        algebra::{linear_form::MultilinearExtension, multilinear_extend},
        protocols::irs_commit::Commitment,
        transcript::{ProverState, VerifierState},
    },
};

struct AxisConfig<'a> {
    eq_memory:       &'a [FieldElement],
    final_timestamp: &'a [FieldElement],
    whir_config:     &'a WhirConfig,
}

#[instrument(skip_all)]
fn prove_axis(
    merlin: &mut ProverState<TranscriptSponge>,
    config: AxisConfig<'_>,
    final_ts_witness: WhirWitness,
    gamma: &FieldElement,
    tau: &FieldElement,
) -> Result<()> {
    let gamma_sq = *gamma * *gamma;

    let (init_vec, final_vec) = rayon::join(
        || {
            config
                .eq_memory
                .par_iter()
                .enumerate()
                .map(|(i, &v)| {
                    let a = FieldElement::from(i as u64);
                    a * gamma_sq + v * gamma - tau
                })
                .collect::<Vec<_>>()
        },
        || {
            config
                .eq_memory
                .par_iter()
                .zip(config.final_timestamp.par_iter())
                .enumerate()
                .map(|(i, (&v, &t))| {
                    let a = FieldElement::from(i as u64);
                    a * gamma_sq + v * gamma + t - tau
                })
                .collect::<Vec<_>>()
        },
    );

    let gpa_randomness = run_gpa2(merlin, &init_vec, &final_vec)?;
    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(1);

    let final_ts_eval = multilinear_extend(config.final_timestamp, evaluation_randomness);
    merlin.prover_hint_ark(&final_ts_eval);

    produce_whir_proof(
        merlin,
        evaluation_randomness,
        &[config.final_timestamp],
        config.whir_config,
        final_ts_witness,
    )?;

    Ok(())
}

#[instrument(skip_all)]
pub fn prove_rowwise(
    merlin: &mut ProverState<TranscriptSponge>,
    final_row: &[FieldElement],
    memory: &Memory,
    whir_configs: &SPARKWHIRConfigs,
    final_row_ts_witness: WhirWitness,
    gamma: &FieldElement,
    tau: &FieldElement,
) -> Result<()> {
    prove_axis(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_rx,
            final_timestamp: final_row,
            whir_config:     &whir_configs.row,
        },
        final_row_ts_witness,
        gamma,
        tau,
    )
}

#[instrument(skip_all)]
pub fn prove_colwise(
    merlin: &mut ProverState<TranscriptSponge>,
    final_col: &[FieldElement],
    memory: &Memory,
    whir_configs: &SPARKWHIRConfigs,
    final_col_ts_witness: WhirWitness,
    gamma: &FieldElement,
    tau: &FieldElement,
) -> Result<()> {
    prove_axis(
        merlin,
        AxisConfig {
            eq_memory:       &memory.eq_ry,
            final_timestamp: final_col,
            whir_config:     &whir_configs.col,
        },
        final_col_ts_witness,
        gamma,
        tau,
    )
}

#[inline]
fn verify_axis(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    num_axis_items: usize,
    whir_config: &WhirConfig,
    finalts_commitment: Commitment<FieldElement>,
    init_mem_fn: impl Fn(&[FieldElement]) -> FieldElement,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
    let gpa_result = gpa_sumcheck_verifier2(
        arthur,
        provekit_common::utils::next_power_of_two(num_axis_items) + 2,
    )?;

    let claimed_init = gpa_result.claimed_values[0];
    let claimed_final = gpa_result.claimed_values[1];
    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let gamma_sq = *gamma * *gamma;

    let init_adr = calculate_adr(evaluation_randomness);
    let init_mem = init_mem_fn(evaluation_randomness);
    let init_opening = init_adr * gamma_sq + init_mem * gamma - tau;

    let final_cntr: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let eval_weight = MultilinearExtension::new(evaluation_randomness.to_vec());
    let finalts_claim = whir_config
        .verify(arthur, &[&finalts_commitment], &[final_cntr])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed: {e}"))?;
    finalts_claim
        .verify([&eval_weight as &dyn whir::algebra::linear_form::LinearForm<FieldElement>])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for final timestamps: {e}"))?;

    let final_opening = init_adr * gamma_sq + init_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    ensure!(claimed_init * claimed_ws == claimed_final * claimed_rs);

    Ok(())
}

#[instrument(skip_all)]
pub fn verify_rowwise(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    num_rows: usize,
    whir_params: &SPARKWHIRConfigs,
    request: &R1CSSparkQuery,
    row_finalts_commitment: Commitment<FieldElement>,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
    verify_axis(
        arthur,
        num_rows,
        &whir_params.row,
        row_finalts_commitment,
        |eval_rand| calculate_eq(&request.point_to_evaluate.row, eval_rand),
        tau,
        gamma,
        claimed_rs,
        claimed_ws,
    )
}

#[instrument(skip_all)]
pub fn verify_colwise(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    num_cols: usize,
    whir_params: &SPARKWHIRConfigs,
    request: &R1CSSparkQuery,
    col_finalts_commitment: Commitment<FieldElement>,
    tau: &FieldElement,
    gamma: &FieldElement,
    claimed_rs: &FieldElement,
    claimed_ws: &FieldElement,
) -> Result<()> {
    verify_axis(
        arthur,
        num_cols,
        &whir_params.col,
        col_finalts_commitment,
        |eval_rand| calculate_eq(&request.point_to_evaluate.col, eval_rand),
        tau,
        gamma,
        claimed_rs,
        claimed_ws,
    )
}

#[instrument(skip_all)]
pub fn produce_whir_proof(
    merlin: &mut ProverState<TranscriptSponge>,
    evaluation_point: &[FieldElement],
    vectors: &[&[FieldElement]],
    config: &WhirConfig,
    witness: WhirWitness,
) -> Result<()> {
    let lf = MultilinearExtension::new(evaluation_point.to_vec());

    let evaluations: Vec<FieldElement> = vectors
        .iter()
        .map(|v| multilinear_extend(v, evaluation_point))
        .collect();

    _ = config.prove(
        merlin,
        vectors.iter().map(|v| Cow::Borrowed(*v)).collect(),
        vec![Cow::Owned(witness)],
        vec![Box::new(lf)
            as Box<
                dyn whir::algebra::linear_form::LinearForm<FieldElement>,
            >],
        Cow::Borrowed(&evaluations),
    );

    Ok(())
}
