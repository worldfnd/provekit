use {
    crate::{
        gpa::gpa_sumcheck_verifier4,
        memory::{verify_colwise, verify_rowwise},
        sumcheck::run_sumcheck_verifier_spark,
        types::{MatrixDimensions, SPARKProof, SPARKWHIRConfigs},
    },
    anyhow::{Context, Result, ensure},
    ark_ff::Field,
    provekit_common::{
        FieldElement, TranscriptSponge, spark::R1CSSparkQuery, utils::next_power_of_two
    },
    whir::{algebra::linear_form::MultilinearExtension, transcript::{DomainSeparator, Proof, VerifierMessage, VerifierState, codecs::Empty}},
};

pub trait SPARKVerifier {
    fn verify(&self, proof: SPARKProof, request: &R1CSSparkQuery) -> Result<()>;
}

pub struct SPARKScheme {
    pub whir_configs:      SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

impl SPARKScheme {
    pub fn from_proof(proof: &SPARKProof) -> Self {
        Self {
            whir_configs:      proof.whir_params.clone(),
            matrix_dimensions: proof.matrix_dimensions.clone(),
        }
    }
}

impl SPARKVerifier for SPARKScheme {
    fn verify(&self, proof: SPARKProof, request: &R1CSSparkQuery) -> Result<()> {
        let ds = DomainSeparator::protocol(&self.whir_configs).instance(&Empty);
        let whir_proof = Proof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        };
        let mut arthur = VerifierState::new(&ds, &whir_proof, TranscriptSponge::default());

        let claimed_value = (request.claimed_value
            / (FieldElement::ONE + request.matrix_batching_randomness))
            / (FieldElement::ONE + request.matrix_batching_randomness);

        let mut new_request = request.clone();
        let b1 = request.matrix_batching_randomness
            / (FieldElement::ONE + request.matrix_batching_randomness);
        new_request.point_to_evaluate.row = std::iter::once(b1)
            .chain(new_request.point_to_evaluate.row.clone())
            .collect();
        new_request.point_to_evaluate.col = std::iter::once(b1)
            .chain(new_request.point_to_evaluate.col.clone())
            .collect();

        verify_spark_single_matrix(
            &self.whir_configs,
            self.matrix_dimensions.clone(),
            &mut arthur,
            &new_request,
            &claimed_value,
        )
    }
}

pub(crate) fn verify_spark_single_matrix(
    whir_params: &SPARKWHIRConfigs,
    matrix_dimensions: MatrixDimensions,
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    request: &R1CSSparkQuery,
    claimed_value: &FieldElement,
) -> Result<()> {
    let val_commitment = whir_params
        .num_terms_1batched
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive val commitment: {e}"))?;
    let rsws_commitment = whir_params
        .num_terms_4batched
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive rsws commitment: {e}"))?;
    let a_row_finalts_commitment = whir_params
        .row
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive row finalts commitment: {e}"))?;
    let a_col_finalts_commitment = whir_params
        .col
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive col finalts commitment: {e}"))?;
    let evalues_commitment = whir_params
        .num_terms_2batched
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive evalues commitment: {e}"))?;

    let (randomness, a_last_sumcheck_value) = run_sumcheck_verifier_spark(
        arthur,
        next_power_of_two(matrix_dimensions.nonzero_terms),
        *claimed_value,
    )
    .context("While verifying SPARK sumcheck")?;
    let eval_weight = MultilinearExtension::new(randomness);

    let sumcheck_hints: [FieldElement; 3] = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    ensure!(a_last_sumcheck_value == sumcheck_hints[0] * sumcheck_hints[1] * sumcheck_hints[2]);

    let e_values_claim = whir_params
        .num_terms_2batched
        .verify(arthur, &[&evalues_commitment], &[
            sumcheck_hints[1],
            sumcheck_hints[2],
        ])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for evalues (sumcheck): {e}"))?;
    e_values_claim
        .verify([&eval_weight as &dyn whir::algebra::linear_form::LinearForm<FieldElement>])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for evalues: {e}"))?;

    let val_claim = whir_params
        .num_terms_1batched
        .verify(arthur, &[&val_commitment], &[sumcheck_hints[0]])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for val: {e}"))?;
    val_claim
        .verify([&eval_weight as &dyn whir::algebra::linear_form::LinearForm<FieldElement>])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for val: {e}"))?;

    let tau: FieldElement = arthur.verifier_message();
    let gamma: FieldElement = arthur.verifier_message();

    let gpa_result = gpa_sumcheck_verifier4(
        arthur,
        provekit_common::utils::next_power_of_two(matrix_dimensions.nonzero_terms) + 3,
    )?;

    let (combination_randomness, evaluation_randomness) = gpa_result.randomness.split_at(2);

    let claimed_row_rs = gpa_result.claimed_values[0];
    let claimed_row_ws = gpa_result.claimed_values[1];
    let claimed_col_rs = gpa_result.claimed_values[2];
    let claimed_col_ws = gpa_result.claimed_values[3];

    let row_adr: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let row_timestamp: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let col_adr: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let col_timestamp: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let gpa_eval_weight = MultilinearExtension::new(evaluation_randomness.to_vec());
    let gpa_eval_lf: &dyn whir::algebra::linear_form::LinearForm<FieldElement> = &gpa_eval_weight;

    let rsws_claim = whir_params
        .num_terms_4batched
        .verify(arthur, &[&rsws_commitment], &[
            row_adr,
            row_timestamp,
            col_adr,
            col_timestamp,
        ])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for rsws: {e}"))?;
    rsws_claim
        .verify([gpa_eval_lf])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for rsws: {e}"))?;

    let row_mem: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let col_mem: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let evalues_gpa_claim = whir_params
        .num_terms_2batched
        .verify(arthur, &[&evalues_commitment], &[row_mem, col_mem])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for evalues (GPA): {e}"))?;
    evalues_gpa_claim
        .verify([gpa_eval_lf])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for evalues (GPA): {e}"))?;

    let gamma_sq = gamma * gamma;

    let row_rs_opening = row_adr * gamma_sq + row_mem * gamma + row_timestamp - tau;
    let row_ws_opening =
        row_adr * gamma_sq + row_mem * gamma + row_timestamp + FieldElement::from(1) - tau;
    let col_rs_opening = col_adr * gamma_sq + col_mem * gamma + col_timestamp - tau;
    let col_ws_opening =
        col_adr * gamma_sq + col_mem * gamma + col_timestamp + FieldElement::from(1) - tau;

    let evaluated_value = row_rs_opening
        * (FieldElement::from(1) - combination_randomness[0])
        * (FieldElement::from(1) - combination_randomness[1])
        + row_ws_opening
            * (FieldElement::from(1) - combination_randomness[0])
            * combination_randomness[1]
        + col_rs_opening
            * combination_randomness[0]
            * (FieldElement::from(1) - combination_randomness[1])
        + col_ws_opening * combination_randomness[0] * combination_randomness[1];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    verify_rowwise(
        arthur,
        matrix_dimensions.num_rows,
        whir_params,
        request,
        a_row_finalts_commitment,
        &tau,
        &gamma,
        &claimed_row_rs,
        &claimed_row_ws,
    )?;

    verify_colwise(
        arthur,
        matrix_dimensions.num_cols,
        whir_params,
        request,
        a_col_finalts_commitment,
        &tau,
        &gamma,
        &claimed_col_rs,
        &claimed_col_ws,
    )?;

    Ok(())
}
