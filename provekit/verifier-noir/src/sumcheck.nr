// Spartan Sumcheck Verifier
//
// Implements run_sumcheck_verifier from provekit/verifier/src/whir_r1cs.rs.
//
// Protocol:
//   1. Squeeze r (m_0 challenges)
//   2. Read sum_g from prover, squeeze rho
//   3. For m_0 rounds:
//      a. Read 4 cubic poly coefficients hhat_i
//      b. Squeeze alpha_i
//      c. Assert: saved == hhat(0) + hhat(1)
//      d. Update: saved = hhat(alpha_i)
//   4. Read blinding_eval, compute f_at_alpha = saved - rho * blinding_eval

use crate::types::eval_cubic_poly;
use crate::transcript::Sponge;

// Data produced by the sumcheck verifier, consumed by the final check.
pub struct SumcheckResult<let M0: u32> {
    pub r: [Field; M0],
    pub alpha: [Field; M0],
    pub blinding_eval: Field,
    pub f_at_alpha: Field,
}

// Run the Spartan sumcheck verifier.
//
// sho: the Fiat-Shamir transcript sponge
// prover_coeffs: the 4*m_0 cubic polynomial coefficients from the prover
//                (parsed from narg_string, in order)
// sum_g: sum_g value from the prover
// blinding_eval: blinding evaluation from the prover
//
// Returns the sumcheck result containing r, alpha, blinding_eval, f_at_alpha.
pub fn run_sumcheck_verifier<let M0: u32>(
    sho: &mut Sponge,
    prover_coeffs: [[Field; 4]; M0],
    sum_g: Field,
    blinding_eval: Field,
) -> SumcheckResult<M0> {
    // Step 1: Squeeze r (m_0 challenges from the transcript)
    let mut r: [Field; M0] = [0; M0];
    for i in 0..M0 {
        r[i] = sho.squeeze_field();
    }

    // Step 2: Absorb sum_g, squeeze rho
    sho.absorb_field(sum_g);
    let rho: Field = sho.squeeze_field();

    // Initialize: saved = rho * sum_g
    let mut saved: Field = rho * sum_g;

    // Step 3: m_0 rounds
    let mut alpha: [Field; M0] = [0; M0];
    for i in 0..M0 {
        let hhat_i = prover_coeffs[i];

        // Absorb the 4 cubic polynomial coefficients
        for j in 0..4 {
            sho.absorb_field(hhat_i[j]);
        }

        // Squeeze alpha_i
        let alpha_i: Field = sho.squeeze_field();
        alpha[i] = alpha_i;

        // Assert: saved == hhat(0) + hhat(1)
        let hhat_at_zero = eval_cubic_poly(hhat_i, 0);
        let hhat_at_one = eval_cubic_poly(hhat_i, 1);
        assert(saved == hhat_at_zero + hhat_at_one, "Sumcheck equality assertion failed");

        // Update: saved = hhat(alpha_i)
        saved = eval_cubic_poly(hhat_i, alpha_i);
    }

    // Step 4: Absorb blinding_eval, compute f_at_alpha
    sho.absorb_field(blinding_eval);
    let f_at_alpha = saved - rho * blinding_eval;

    SumcheckResult {
        r,
        alpha,
        blinding_eval,
        f_at_alpha,
    }
}
