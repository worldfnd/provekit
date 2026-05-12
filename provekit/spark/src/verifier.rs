use {
    crate::{
        gpa::gpa_sumcheck_verifier4,
        memory::verify_axis,
        setup::PrecomputedCommitments,
        sumcheck::{run_parallel_sumchecks_verifier, run_sumcheck_verifier_spark},
        types::{MatrixDimensions, SPARKProof, SPARKSetup, SPARKWHIRConfigs},
    },
    anyhow::{ensure, Context, Result},
    ark_ff::{AdditiveGroup, Field, Zero},
    provekit_common::{
        spark::{hash_query_set, Point, R1CSSparkQuery},
        utils::{next_power_of_two, sumcheck::calculate_eq},
        FieldElement, TranscriptSponge,
    },
    tracing::instrument,
    whir::{
        algebra::linear_form::MultilinearExtension,
        transcript::{DomainSeparator, Proof, VerifierMessage, VerifierState},
    },
};

pub trait SPARKVerifier {
    fn verify(
        &self,
        proof: SPARKProof,
        setup: &SPARKSetup,
        requests: &[R1CSSparkQuery],
    ) -> Result<()>;
}

pub struct SPARKScheme;

impl SPARKVerifier for SPARKScheme {
    #[instrument(skip_all)]
    fn verify(
        &self,
        proof: SPARKProof,
        setup: &SPARKSetup,
        requests: &[R1CSSparkQuery],
    ) -> Result<()> {
        ensure!(
            !requests.is_empty(),
            "SPARK verifier needs at least one request"
        );

        let precomputed_commitments = setup.extract_commitments()?;

        let whir_proof = Proof {
            narg_string: proof.0.narg_string,
            hints: proof.0.hints,
            #[cfg(debug_assertions)]
            pattern: proof.0.pattern,
        };
        let mut arthur = VerifierState::new(
            &DomainSeparator::protocol(&setup.whir_configs)
                .session(&setup.transcript.narg_string)
                .instance(&hash_query_set(requests)),
            &whir_proof,
            TranscriptSponge::default(),
        );

        let request = if requests.len() == 1 {
            requests[0].clone()
        } else {
            let beta: FieldElement = arthur.verifier_message();

            let mut claimed_evals = [FieldElement::ZERO; 3];
            let mut beta_pow = FieldElement::ONE;
            for request in requests {
                claimed_evals[0] += beta_pow * request.claimed_a;
                claimed_evals[1] += beta_pow * request.claimed_b;
                claimed_evals[2] += beta_pow * request.claimed_c;
                beta_pow *= beta;
            }

            let domain_size = setup.matrix_dimensions.num_cols / 2;
            ensure!(
                domain_size.is_power_of_two(),
                "SPARK domain_size must be a power of two (got {domain_size})"
            );
            let variable_count = domain_size.ilog2() as usize;
            let (final_claims, folded, folding_randomness) =
                run_parallel_sumchecks_verifier(&mut arthur, variable_count, claimed_evals)
                    .context("verifying parallel sumchecks")?;

            let mut h_at_fr = FieldElement::ZERO;
            let mut beta_pow = FieldElement::ONE;
            for request in requests {
                h_at_fr +=
                    beta_pow * calculate_eq(&request.point_to_evaluate.col, &folding_randomness);
                beta_pow *= beta;
            }
            ensure!(
                final_claims[0] == h_at_fr * folded[0],
                "parallel sumcheck final-equation check failed (a)"
            );
            ensure!(
                final_claims[1] == h_at_fr * folded[1],
                "parallel sumcheck final-equation check failed (b)"
            );
            ensure!(
                final_claims[2] == h_at_fr * folded[2],
                "parallel sumcheck final-equation check failed (c)"
            );

            R1CSSparkQuery {
                point_to_evaluate: Point {
                    row: requests[0].point_to_evaluate.row.clone(),
                    col: folding_randomness,
                },
                claimed_a:         folded[0],
                claimed_b:         folded[1],
                claimed_c:         folded[2],
            }
        };

        let r: FieldElement = arthur.verifier_message();
        ensure!(
            !(FieldElement::ONE + r).is_zero(),
            "SPARK RLC randomness must not equal -1 (would zero the denominator)"
        );

        let b1 = r / (FieldElement::ONE + r);
        let combined = request.claimed_a + r * request.claimed_b + r * r * request.claimed_c;
        let claimed_value = combined / (FieldElement::ONE + r) / (FieldElement::ONE + r);

        let mut new_request = request.clone();
        new_request.point_to_evaluate.row = std::iter::once(b1)
            .chain(new_request.point_to_evaluate.row.clone())
            .collect();
        new_request.point_to_evaluate.col = std::iter::once(b1)
            .chain(new_request.point_to_evaluate.col.clone())
            .collect();

        verify_spark_single_matrix(
            &setup.whir_configs,
            setup.matrix_dimensions.clone(),
            &mut arthur,
            &precomputed_commitments,
            &new_request,
            &claimed_value,
        )
    }
}

#[instrument(skip_all)]
pub(crate) fn verify_spark_single_matrix(
    whir_configs: &SPARKWHIRConfigs,
    matrix_dimensions: MatrixDimensions,
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    precomputed_commitments: &PrecomputedCommitments,
    request: &R1CSSparkQuery,
    claimed_value: &FieldElement,
) -> Result<()> {
    let e_values_commitment = whir_configs
        .num_terms_2batched
        .receive_commitment(arthur)
        .map_err(|e| anyhow::anyhow!("Failed to receive e_values commitment: {e}"))?;

    let (randomness, last_sumcheck_value) = run_sumcheck_verifier_spark(
        arthur,
        next_power_of_two(matrix_dimensions.nonzero_terms),
        *claimed_value,
    )
    .context("While verifying SPARK sumcheck")?;
    let eval_weight = MultilinearExtension::new(randomness);

    let sumcheck_hints: [FieldElement; 3] = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read SPARK sumcheck final folds hint"))?;

    ensure!(
        last_sumcheck_value == sumcheck_hints[0] * sumcheck_hints[1] * sumcheck_hints[2],
        "SPARK sumcheck final folds inconsistent with claimed last value"
    );

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
        .map_err(|_| anyhow::anyhow!("Failed to read row_adr hint"))?;
    let row_timestamp: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read row_timestamp hint"))?;
    let col_adr: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read col_adr hint"))?;
    let col_timestamp: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read col_timestamp hint"))?;

    let gpa_eval_weight = MultilinearExtension::new(evaluation_randomness.to_vec());
    let gpa_eval_lf: &dyn whir::algebra::linear_form::LinearForm<FieldElement> = &gpa_eval_weight;

    let row_field_at_fold: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read row_field_at_fold hint"))?;
    let read_row_at_fold: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read read_row_at_fold hint"))?;
    let col_field_at_fold: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read col_field_at_fold hint"))?;
    let read_col_at_fold: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read read_col_at_fold hint"))?;
    let vals_at_eval: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read vals_at_eval hint"))?;

    let fold_lf_for_vals_rs_ws = MultilinearExtension::new(eval_weight.point.clone());
    let eval_lf_for_vals_rs_ws = MultilinearExtension::new(evaluation_randomness.to_vec());

    let vals_rs_ws_claim = whir_configs
        .num_terms_5batched
        .verify(arthur, &[&precomputed_commitments.vals_rsws], &[
            // fold_lf
            sumcheck_hints[0],
            row_field_at_fold,
            read_row_at_fold,
            col_field_at_fold,
            read_col_at_fold,
            // eval_lf
            vals_at_eval,
            row_adr,
            row_timestamp,
            col_adr,
            col_timestamp,
        ])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for vals_rs_ws: {e}"))?;
    vals_rs_ws_claim
        .verify([
            &fold_lf_for_vals_rs_ws as &dyn whir::algebra::linear_form::LinearForm<FieldElement>,
            &eval_lf_for_vals_rs_ws as &dyn whir::algebra::linear_form::LinearForm<FieldElement>,
        ])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for vals_rs_ws: {e}"))?;

    let row_mem: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read row_mem hint"))?;
    let col_mem: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read col_mem hint"))?;

    let e_values_combined_claim = whir_configs
        .num_terms_2batched
        .verify(arthur, &[&e_values_commitment], &[
            sumcheck_hints[1],
            sumcheck_hints[2],
            row_mem,
            col_mem,
        ])
        .map_err(|e| anyhow::anyhow!("WHIR verify failed for e_values (combined): {e}"))?;
    e_values_combined_claim
        .verify([
            &eval_weight as &dyn whir::algebra::linear_form::LinearForm<FieldElement>,
            gpa_eval_lf,
        ])
        .map_err(|e| anyhow::anyhow!("FinalClaim check failed for e_values (combined): {e}"))?;

    let gamma_sq = gamma * gamma;

    let row_rs_opening = row_adr * gamma_sq + row_mem * gamma + row_timestamp - tau;
    let row_ws_opening =
        row_adr * gamma_sq + row_mem * gamma + row_timestamp + FieldElement::ONE - tau;
    let col_rs_opening = col_adr * gamma_sq + col_mem * gamma + col_timestamp - tau;
    let col_ws_opening =
        col_adr * gamma_sq + col_mem * gamma + col_timestamp + FieldElement::ONE - tau;

    let evaluated_value = row_rs_opening
        * (FieldElement::ONE - combination_randomness[0])
        * (FieldElement::ONE - combination_randomness[1])
        + row_ws_opening
            * (FieldElement::ONE - combination_randomness[0])
            * combination_randomness[1]
        + col_rs_opening
            * combination_randomness[0]
            * (FieldElement::ONE - combination_randomness[1])
        + col_ws_opening * combination_randomness[0] * combination_randomness[1];

    ensure!(
        evaluated_value == gpa_result.last_sumcheck_value,
        "rs/ws GPA sumcheck final value inconsistent with evaluated multilinear extension"
    );

    verify_axis(
        arthur,
        matrix_dimensions.num_rows,
        &whir_configs.row,
        &precomputed_commitments.a_row_finalts,
        |eval_rand| calculate_eq(&request.point_to_evaluate.row, eval_rand),
        &tau,
        &gamma,
        &claimed_row_rs,
        &claimed_row_ws,
    )?;

    verify_axis(
        arthur,
        matrix_dimensions.num_cols,
        &whir_configs.col,
        &precomputed_commitments.a_col_finalts,
        |eval_rand| calculate_eq(&request.point_to_evaluate.col, eval_rand),
        &tau,
        &gamma,
        &claimed_col_rs,
        &claimed_col_ws,
    )?;

    Ok(())
}
