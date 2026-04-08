//! Twist verifier: verifies the Twist sumcheck within the Fiat-Shamir
//! transcript.

use {
    anyhow::{ensure, Result},
    ark_std::Zero,
    provekit_common::{
        twist::{
            sumcheck::{eval_round_poly, verify_round, DEGREE_PLUS_ONE},
            TwistSchemeInfo,
        },
        utils::sumcheck::calculate_eq,
        FieldElement, TranscriptSponge,
    },
    tracing::instrument,
    whir::transcript::{VerifierMessage, VerifierState},
};

/// Data returned from the Twist sumcheck verifier.
pub struct TwistVerifyResult {
    /// Evaluation point (sequence of challenges from each sumcheck round).
    pub tau: Vec<FieldElement>,
    /// Evaluations of the 6 Twist polynomials at tau (from hints).
    pub evals: [FieldElement; 6],
}

/// Run the Twist sumcheck verifier within the Fiat-Shamir transcript.
///
/// Verifies the degree-4 sumcheck proving RAM consistency, then reads
/// polynomial evaluations from hints and checks the final evaluation claim.
#[instrument(skip_all)]
pub fn run_twist_sumcheck_verifier(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    twist_info: &TwistSchemeInfo,
) -> Result<TwistVerifyResult> {
    let num_vars = twist_info.num_vars;

    // Get randomness from transcript (must match prover)
    let r: Vec<FieldElement> = arthur.verifier_message_vec(num_vars);
    let beta: [FieldElement; 2] = [arthur.verifier_message(), arthur.verifier_message()];

    // Initial claimed sum is 0 (Twist constraint sums to zero for valid traces)
    let mut claimed_sum = FieldElement::zero();

    let mut tau = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        // Read the 5 evaluation points from the proof
        let mut round_poly = [FieldElement::zero(); DEGREE_PLUS_ONE];
        for coeff in &mut round_poly {
            *coeff = arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read Twist round {round} coefficient"))?;
        }

        // Receive challenge (must match prover)
        let alpha_i: FieldElement = arthur.verifier_message();
        tau.push(alpha_i);

        // Verify: p(0) + p(1) == claimed_sum
        ensure!(
            verify_round(&round_poly, claimed_sum),
            "Twist sumcheck round {round} failed: p(0)+p(1) != claimed_sum"
        );

        // Update claimed sum for next round
        claimed_sum = eval_round_poly(&round_poly, alpha_i);
    }

    // Read the 6 polynomial evaluations from hints
    let evals: [FieldElement; 6] = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read Twist evaluation hints"))?;

    // Verify the final sumcheck claim against the evaluations
    let [inc_tau, is_write_tau, val_tau, val_prev_tau, addr_tau, addr_prev_tau] = evals;
    let one = FieldElement::from(1u64);
    let value_check = inc_tau * (one - is_write_tau) * (val_tau - val_prev_tau);
    let addr_check = inc_tau * (addr_tau - addr_prev_tau);
    let eq_r_tau = calculate_eq(&r, &tau);
    let expected = eq_r_tau * (beta[0] * value_check + beta[1] * addr_check);

    ensure!(
        claimed_sum == expected,
        "Twist sumcheck final evaluation mismatch"
    );

    Ok(TwistVerifyResult { tau, evals })
}
