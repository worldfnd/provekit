use {
    anyhow::{ensure, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::{
            sumcheck::{eval_cubic_poly, sumcheck_fold_map_reduce},
            HALF,
        },
        FieldElement,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
        ProverState, VerifierState,
    },
};

/// Runs sumcheck protocol for SPARK matrix evaluation.
///
/// Proves that `∑ m₀(x) · m₁(x) · m₂(x) = claimed_value` over the boolean
/// hypercube without revealing individual polynomial values.
///
/// # Returns
///
/// Tuple of `(final_folded_values, accumulated_randomness)`
pub fn run_spark_sumcheck(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    mles: [Vec<FieldElement>; 3],
    mut claimed_value: FieldElement,
) -> Result<([FieldElement; 3], Vec<FieldElement>)> {
    let mut sumcheck_randomness = [FieldElement::from(0)];
    let mut sumcheck_randomness_accumulator = Vec::<FieldElement>::new();
    let mut fold = None;

    let mut m0 = mles[0].clone();
    let mut m1 = mles[1].clone();
    let mut m2 = mles[2].clone();

    loop {
        // Evaluate cubic at special points: 0, -1, ∞
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut m0, &mut m1, &mut m2], fold, |[m0, m1, m2]| {
                [
                    m0.0 * m1.0 * m2.0,
                    (m0.0 + m0.0 - m0.1) * (m1.0 + m1.0 - m1.1) * (m2.0 + m2.0 - m2.1),
                    (m0.1 - m0.0) * (m1.1 - m1.0) * (m2.1 - m2.0),
                ]
            });

        if fold.is_some() {
            m0.truncate(m0.len() / 2);
            m1.truncate(m1.len() / 2);
            m2.truncate(m2.len() / 2);
        }

        let mut hhat_i_coeffs = [FieldElement::from(0); 4];

        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] =
            HALF * (claimed_value + hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = claimed_value
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        assert_eq!(
            claimed_value,
            hhat_i_coeffs[0]
                + hhat_i_coeffs[0]
                + hhat_i_coeffs[1]
                + hhat_i_coeffs[2]
                + hhat_i_coeffs[3],
            "Sumcheck binding check failed"
        );

        merlin.add_scalars(&hhat_i_coeffs[..])?;
        merlin.fill_challenge_scalars(&mut sumcheck_randomness)?;
        fold = Some(sumcheck_randomness[0]);
        claimed_value = eval_cubic_poly(hhat_i_coeffs, sumcheck_randomness[0]);
        sumcheck_randomness_accumulator.push(sumcheck_randomness[0]);
        if m0.len() <= 2 {
            break;
        }
    }

    let folded_v0 = m0[0] + (m0[1] - m0[0]) * sumcheck_randomness[0];
    let folded_v1 = m1[0] + (m1[1] - m1[0]) * sumcheck_randomness[0];
    let folded_v2 = m2[0] + (m2[1] - m2[0]) * sumcheck_randomness[0];

    Ok((
        [folded_v0, folded_v1, folded_v2],
        sumcheck_randomness_accumulator,
    ))
}

/// Verifies a SPARK sumcheck proof from the transcript.
///
/// Checks that the prover's claimed sum is correct by verifying polynomial
/// evaluations at each round without recomputing the full sum.
///
/// # Returns
///
/// Tuple of `(accumulated_randomness, final_evaluation)`
pub fn run_sumcheck_verifier_spark(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    variable_count: usize,
    initial_sumcheck_val: FieldElement,
) -> Result<(Vec<FieldElement>, FieldElement)> {
    let mut saved_val_for_sumcheck_equality_assertion = initial_sumcheck_val;

    let mut alpha = vec![FieldElement::zero(); variable_count];

    for i in 0..variable_count {
        let mut hhat_i = [FieldElement::zero(); 4];
        let mut alpha_i = [FieldElement::zero(); 1];
        arthur.fill_next_scalars(&mut hhat_i)?;
        arthur.fill_challenge_scalars(&mut alpha_i)?;
        alpha[i] = alpha_i[0];

        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality check failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i[0]);
    }

    Ok((alpha, saved_val_for_sumcheck_equality_assertion))
}
