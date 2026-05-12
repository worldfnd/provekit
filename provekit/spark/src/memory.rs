use {
    crate::{
        gpa::{calculate_adr, gpa_sumcheck_verifier2, run_gpa2},
        types::{Challenges, WhirWitness},
    },
    anyhow::{ensure, Result},
    ark_ff::AdditiveGroup,
    ark_std::One,
    provekit_common::{FieldElement, TranscriptSponge, WhirConfig},
    rayon::prelude::*,
    std::borrow::Cow,
    tracing::instrument,
    whir::{
        algebra::{linear_form::MultilinearExtension, multilinear_extend},
        protocols::irs_commit::Commitment,
        transcript::{ProverState, VerifierState},
    },
};

pub struct AxisConfig<'a> {
    pub eq_memory:       &'a [FieldElement],
    pub final_timestamp: &'a [FieldElement],
    pub whir_config:     &'a WhirConfig,
}

#[instrument(skip_all)]
pub fn prove_axis_init_final_product(
    merlin: &mut ProverState<TranscriptSponge>,
    config: AxisConfig<'_>,
    final_ts_witness: &WhirWitness,
    challenges: &Challenges,
) -> Result<()> {
    let gamma = &challenges.gamma;
    let tau = &challenges.tau;
    let gamma_sq = *gamma * *gamma;

    let n = config.eq_memory.len();
    debug_assert_eq!(
        config.final_timestamp.len(),
        n,
        "eq_memory and final_timestamp must have equal length"
    );

    // Per element:
    //   init[i]  = i*gamma_sq + eq[i]*gamma - tau
    //   final[i] = init[i] + final_ts[i]
    let gpa_leaves = tracing::info_span!("build_init_final_vecs").in_scope(|| {
        let mut buf = vec![FieldElement::ZERO; 2 * n];
        let (init_section, final_section) = buf.split_at_mut(n);

        init_section
            .par_iter_mut()
            .zip(final_section.par_iter_mut())
            .enumerate()
            .for_each(|(i, (init_slot, final_slot))| {
                let base =
                    FieldElement::from(i as u64) * gamma_sq + config.eq_memory[i] * gamma - tau;
                *init_slot = base;
                *final_slot = base + config.final_timestamp[i];
            });
        buf
    });

    let gpa_randomness = run_gpa2(merlin, gpa_leaves)?;
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
pub fn verify_axis(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    num_axis_items: usize,
    whir_config: &WhirConfig,
    finalts_commitment: &Commitment<FieldElement>,
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
        .map_err(|_| anyhow::anyhow!("Failed to read final counter hint"))?;

    let eval_weight = MultilinearExtension::new(evaluation_randomness.to_vec());
    let finalts_claim = whir_config
        .verify(arthur, &[finalts_commitment], &[final_cntr])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed: {e}"))?;
    finalts_claim
        .verify([&eval_weight as &dyn whir::algebra::linear_form::LinearForm<FieldElement>])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for final timestamps: {e}"))?;

    let final_opening = init_adr * gamma_sq + init_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(
        evaluated_value == gpa_result.last_sumcheck_value,
        "init/final GPA sumcheck final value inconsistent with evaluated multilinear extension"
    );

    ensure!(
        claimed_init * claimed_ws == claimed_final * claimed_rs,
        "memory-checking product mismatch: init * ws != final * rs"
    );

    Ok(())
}

#[instrument(skip_all)]
pub fn produce_whir_proof(
    merlin: &mut ProverState<TranscriptSponge>,
    evaluation_point: &[FieldElement],
    vectors: &[&[FieldElement]],
    config: &WhirConfig,
    witness: &WhirWitness,
) -> Result<()> {
    let lf = MultilinearExtension::new(evaluation_point.to_vec());

    let evaluations: Vec<FieldElement> = vectors
        .iter()
        .map(|v| multilinear_extend(v, evaluation_point))
        .collect();

    _ = config.prove(
        merlin,
        vectors.iter().map(|v| Cow::Borrowed(*v)).collect(),
        vec![Cow::Borrowed(witness)],
        vec![Box::new(lf)
            as Box<
                dyn whir::algebra::linear_form::LinearForm<FieldElement>,
            >],
        Cow::Borrowed(&evaluations),
    );

    Ok(())
}
