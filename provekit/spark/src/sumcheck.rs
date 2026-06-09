use {
    crate::utils::read_hint,
    anyhow::{ensure, Result},
    ark_std::{One, Zero},
    provekit_common::{
        utils::{
            sumcheck::{eval_cubic_poly, eval_quadratic_poly, sumcheck_fold_map_reduce},
            HALF,
        },
        FieldElement, TranscriptSponge,
    },
    tracing::instrument,
    whir::transcript::{ProverState, VerifierMessage, VerifierState},
};

#[instrument(skip_all)]
pub fn run_spark_sumcheck(
    merlin: &mut ProverState<TranscriptSponge>,
    mles: [&[FieldElement]; 3],
    mut claimed_value: FieldElement,
) -> Result<([FieldElement; 3], Vec<FieldElement>)> {
    let mut sumcheck_randomness;
    let mut sumcheck_randomness_accumulator = Vec::<FieldElement>::new();
    let mut fold = None;

    let mut m0 = mles[0].to_vec();
    let mut m1 = mles[1].to_vec();
    let mut m2 = mles[2].to_vec();

    loop {
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

        let mut hhat_i_coeffs = [FieldElement::zero(); 4];

        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] =
            HALF * (claimed_value + hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = claimed_value
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        ensure!(
            claimed_value
                == hhat_i_coeffs[0]
                    + hhat_i_coeffs[0]
                    + hhat_i_coeffs[1]
                    + hhat_i_coeffs[2]
                    + hhat_i_coeffs[3],
            "Sumcheck binding check failed"
        );

        for coeff in &hhat_i_coeffs {
            merlin.prover_message(coeff);
        }
        sumcheck_randomness = merlin.verifier_message();
        fold = Some(sumcheck_randomness);
        claimed_value = eval_cubic_poly(hhat_i_coeffs, sumcheck_randomness);
        sumcheck_randomness_accumulator.push(sumcheck_randomness);
        if m0.len() <= 2 {
            break;
        }
    }

    let folded_v0 = m0[0] + (m0[1] - m0[0]) * sumcheck_randomness;
    let folded_v1 = m1[0] + (m1[1] - m1[0]) * sumcheck_randomness;
    let folded_v2 = m2[0] + (m2[1] - m2[0]) * sumcheck_randomness;

    Ok((
        [folded_v0, folded_v1, folded_v2],
        sumcheck_randomness_accumulator,
    ))
}

#[instrument(skip_all)]
pub fn run_parallel_sumchecks_verifier(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    variable_count: usize,
    mut claimed_values: [FieldElement; 3],
) -> Result<([FieldElement; 3], [FieldElement; 3], Vec<FieldElement>)> {
    let mut folding_randomness = Vec::with_capacity(variable_count);

    for _ in 0..variable_count {
        let a_coeffs: [FieldElement; 3] = [
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck a_coeffs[0]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck a_coeffs[1]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck a_coeffs[2]"))?,
        ];
        let b_coeffs: [FieldElement; 3] = [
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck b_coeffs[0]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck b_coeffs[1]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck b_coeffs[2]"))?,
        ];
        let c_coeffs: [FieldElement; 3] = [
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck c_coeffs[0]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck c_coeffs[1]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read parallel sumcheck c_coeffs[2]"))?,
        ];

        ensure!(
            claimed_values[0] == a_coeffs[0] + a_coeffs[0] + a_coeffs[1] + a_coeffs[2],
            "parallel sumcheck equality failed (a)"
        );
        ensure!(
            claimed_values[1] == b_coeffs[0] + b_coeffs[0] + b_coeffs[1] + b_coeffs[2],
            "parallel sumcheck equality failed (b)"
        );
        ensure!(
            claimed_values[2] == c_coeffs[0] + c_coeffs[0] + c_coeffs[1] + c_coeffs[2],
            "parallel sumcheck equality failed (c)"
        );

        let alpha_i: FieldElement = arthur.verifier_message();
        folding_randomness.push(alpha_i);

        claimed_values[0] = eval_quadratic_poly(a_coeffs, alpha_i);
        claimed_values[1] = eval_quadratic_poly(b_coeffs, alpha_i);
        claimed_values[2] = eval_quadratic_poly(c_coeffs, alpha_i);
    }

    let folded: [FieldElement; 3] = read_hint(arthur, "parallel sumcheck folded values")?;

    Ok((claimed_values, folded, folding_randomness))
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier_spark(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    variable_count: usize,
    initial_sumcheck_val: FieldElement,
) -> Result<(Vec<FieldElement>, FieldElement)> {
    let mut saved_val_for_sumcheck_equality_assertion = initial_sumcheck_val;

    let mut alpha = vec![FieldElement::zero(); variable_count];

    for i in 0..variable_count {
        let hhat_i: [FieldElement; 4] = [
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read SPARK sumcheck hhat_i[0]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read SPARK sumcheck hhat_i[1]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read SPARK sumcheck hhat_i[2]"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read SPARK sumcheck hhat_i[3]"))?,
        ];
        let alpha_i: FieldElement = arthur.verifier_message();
        alpha[i] = alpha_i;

        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality check failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i);
    }

    Ok((alpha, saved_val_for_sumcheck_equality_assertion))
}
