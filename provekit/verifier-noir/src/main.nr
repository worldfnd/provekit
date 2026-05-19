// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 3C: integrated `main.nr` orchestration skeleton.
//
// IMPORTANT: WHIR low-degree-test (LDT) internals are STUBBED with TODO
// comments. The Merkle openings, in-domain consistency checks, and the inner
// WHIR sumcheck-with-folding are NOT performed -- only the transcript absorbs
// of the inner-WHIR prover messages are done so the outer-Spartan flow's
// Fiat-Shamir transcript continues to evolve correctly.
//
// SOUNDNESS: this verifier in its current state IS NOT SOUND. Subsequent
// atoms will harden each stubbed phase.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;
mod public_input;

mod types;
mod matrices;
mod whir;

use crate::matrices::{A_TRIPLES, B_TRIPLES, C_TRIPLES};
use crate::matrix_eval::multiply_matrix_by_eq;
use crate::sumcheck::{calculate_eq, run_sumcheck_verifier};
use crate::transcript::Transcript;
use crate::types::{
    BLINDING_OOD_COUNT, BLINDING_OOD_POINTS, FINAL_POW_BITS, FINAL_SUMCHECK_ROUNDS,
    INITIAL_OOD_COUNT, INITIAL_SUMCHECK_ROUNDS, M_0, NUM_CONSTRAINTS, NUM_WHIR_ROUNDS,
    NUM_WITNESSES, ROUND_POW_BITS_0, ROUND_POW_BITS_1, ROUND_POW_BITS_2,
    SUMCHECK_POLY_COEFFS, W_FOLDED_BLINDING_EVALS_LEN,
};
use crate::whir::{receive_commitment, verify_pow, Commitment};

/// Bundle of all witness-side proof data the verifier consumes.
///
/// Field layout is keyed to the basic-2 zkWHIR shape (`types.nr`); regenerate
/// the Prover.toml whenever the shape changes.
///
/// All values are private witness inputs. For basic-2, NUM_PUBLIC_INPUTS = 0
/// and Noir does not allow zero-sized arrays in `main`'s signature, so the
/// `public_inputs: pub [Field; N]` parameter is omitted entirely for this
/// shape. When the codegen tool emits a shape with N > 0, this parameter
/// must be added back.
/// TODO(codegen): generate `main`'s signature so empty-array shapes are
/// gracefully omitted and non-empty shapes are added back as `pub`.
fn main(
    // --- Transcript pre-absorbed state (codegen Rust-side) ---
    // TODO(codegen-soundness): currently shipped as private witness with no
    // in-circuit verification that this state matches the domain-separator +
    // instance replay. A future atom must either bind it to known constants
    // or include domain-separator replay in the circuit.
    pre_absorbed_state: [Field; 4],
    pre_absorbed_absorb_pos: u32,
    pre_absorbed_squeeze_pos: u32,

    // --- Outer Spartan: commitment 1a (witness-side blinded IRS commitment) ---
    initial_root: Field,
    initial_ood_evals: [Field; INITIAL_OOD_COUNT],

    // --- Outer Spartan: commitment 1b (blinding-side IRS commitment) ---
    // Part of `receive_commitments(_, 1)` in the Rust verifier: both the
    // blinded and blinding commitments are absorbed before the Spartan sumcheck.
    blinding_initial_root: Field,
    blinding_initial_ood_evals: [Field; BLINDING_OOD_COUNT],

    // --- Outer Spartan: sumcheck prover messages ---
    sum_g: Field,
    sumcheck_h_polys: [[Field; SUMCHECK_POLY_COEFFS]; M_0],
    blinding_eval: Field,

    // --- Outer Spartan: A/B/C evaluation hints ---
    evals_az: Field,
    evals_bz: Field,
    evals_cz: Field,

    // --- zkWHIR layer: witness-side blinded commitment messages ---
    // Absorbed `w_folded_blinding_evals` (witness x polys x (num_witness_vars+1)).
    w_folded_blinding_evals: [Field; W_FOLDED_BLINDING_EVALS_LEN],

    // Initial WHIR commitment for the witness-side blinded commitment.
    witness_initial_root: Field,
    witness_initial_ood_evals: [Field; INITIAL_OOD_COUNT],

    // Per-h_gamma per-poly: m_eval + 13 g_hat_evals. h_gammas =
    //   INITIAL_OOD_COUNT * INTERLEAVING_DEPTH = 1 * 8 = 8 for basic-2.
    //   total m_evals = 8 (gammas) * 1 (polys) = 8
    //   total g_hat_evals = 8 (gammas) * 1 (polys) * 13 (num_witness_variables) = 104
    witness_m_evals: [Field; 8],
    witness_g_hat_evals: [Field; 104],

    // After per-poly accumulation, the prover sends the combined and
    // batched-h claim vectors (size = num_polynomials = 1).
    combined_claims: [Field; 1],
    batched_h_claims: [Field; 1],

    // --- WHIR inner-LDT prover messages (STUBBED, absorbed only) ---
    // TODO(soundness): These messages currently flow only through the
    // transcript -- no Merkle path verification, no in-domain consistency,
    // no inner-sumcheck-with-folding is performed.
    //
    // For each of NUM_WHIR_ROUNDS rounds we expect:
    //   - a Merkle root         (Field)
    //   - INITIAL_OOD_COUNT     OOD evaluations
    //   - INITIAL_SUMCHECK_ROUNDS sumcheck round polynomials, each 4 coeffs
    //   - a PoW nonce           (u64 packed into [u8;8])
    whir_round_roots: [Field; NUM_WHIR_ROUNDS],
    whir_round_ood_evals: [[Field; INITIAL_OOD_COUNT]; NUM_WHIR_ROUNDS],
    whir_round_sumcheck_polys: [[[Field; SUMCHECK_POLY_COEFFS]; INITIAL_SUMCHECK_ROUNDS]; NUM_WHIR_ROUNDS],
    whir_round_pow_nonces: [[u8; 8]; NUM_WHIR_ROUNDS],

    // Final WHIR sumcheck (after the last folding round): FINAL_SUMCHECK_ROUNDS
    // round polynomials and a final PoW nonce.
    whir_final_sumcheck_polys: [[Field; SUMCHECK_POLY_COEFFS]; FINAL_SUMCHECK_ROUNDS],
    whir_final_pow_nonce: [u8; 8],

    // Final folded polynomial coefficients (size = 2^FINAL_FOLDING_FACTOR).
    // For basic-2 with initial_folding_factor = 3 and three rounds, the final
    // polynomial after all folds has 2 coefficients (degree-1 univariate).
    // TODO(codegen): emit FINAL_POLYNOMIAL_LEN explicitly from codegen.
    whir_final_polynomial: [Field; 2],
) {
    // -------------------------------------------------------------------
    // Step 1: Initialize the Fiat-Shamir transcript from the pre-absorbed
    // state computed Rust-side (domain separator + instance already absorbed).
    // -------------------------------------------------------------------
    let mut t = Transcript::init_from_pre_absorbed_state(
        pre_absorbed_state,
        pre_absorbed_absorb_pos,
        pre_absorbed_squeeze_pos,
    );

    // -------------------------------------------------------------------
    // Step 2: Receive the witness-side initial IRS commitment (root +
    // INITIAL_OOD_COUNT OOD evaluations).
    // -------------------------------------------------------------------
    // INITIAL_OOD_COUNT = out_domain_samples = num_vectors = 1 for the blinded commitment.
    let commitment_1 = Commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT> {
        root: initial_root,
        ood_evals: initial_ood_evals,
    };
    // ood_points discarded: in-domain consistency checks are stubbed (TODO(soundness)).
    let _ood_points_1 = receive_commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT>(&mut t, commitment_1);

    // Step 2b: Receive the blinding-side commitment (also part of
    // `receive_commitments(_, 1)` in the Rust verifier: absorbs root,
    // squeezes OOD points, absorbs OOD evals).
    // BLINDING_OOD_POINTS = out_domain_samples, BLINDING_OOD_COUNT = out_domain_samples * num_vectors.
    let blinding_commitment_1 = Commitment::<BLINDING_OOD_POINTS, BLINDING_OOD_COUNT> {
        root: blinding_initial_root,
        ood_evals: blinding_initial_ood_evals,
    };
    // ood_points discarded: in-domain consistency checks are stubbed (TODO(soundness)).
    let _ood_points_blinding_1 = receive_commitment::<BLINDING_OOD_POINTS, BLINDING_OOD_COUNT>(&mut t, blinding_commitment_1);

    // Step 3: NUM_CHALLENGES = 0 for basic-2 -- skip the LogUp branch.

    // -------------------------------------------------------------------
    // Step 4: Run the outer Spartan sumcheck (M_0 rounds, cubic polys).
    // -------------------------------------------------------------------
    let sumcheck_result = run_sumcheck_verifier::<M_0>(
        &mut t,
        sum_g,
        sumcheck_h_polys,
        blinding_eval,
    );

    // Step 5: NUM_PUBLIC_INPUTS = 0 for basic-2 -- skip the public input
    // hash absorb and binding check.

    // -------------------------------------------------------------------
    // Step 6: Squeeze the random batching challenge `x`.
    // -------------------------------------------------------------------
    let _x: Field = t.squeeze_field();

    // -------------------------------------------------------------------
    // Step 7: Compute A/B/C-times-eq(alpha) sparse matrix evaluations.
    //
    // For basic-2 NUM_CONSTRAINTS = 1, so the eq vector over the constraint
    // hypercube has length 1. With LOG_NUM_CONSTRAINTS = 0, we pass alpha
    // restricted to its first 0 coordinates (none), and the eq evaluation
    // is the constant 1.
    // -------------------------------------------------------------------
    let alpha = sumcheck_result.alpha;

    // For LOG_NUM_CONSTRAINTS = 0 (basic-2), eq_hypercube_evals over an empty
    // alpha returns a single-entry array `[1]`. Compute it manually since
    // calling eq_hypercube_evals with LOG_N=0 isn't well-formed when the
    // alpha array would need to be zero-length and N=1.
    //
    // TODO(generalize): when NUM_CONSTRAINTS > 1 we need a `LOG_NUM_CONSTRAINTS`
    // prefix of `alpha`. For now, basic-2 special-case.
    let eq_evals: [Field; NUM_CONSTRAINTS] = [1];

    // Multiply each transposed matrix by the eq vector to get the per-column
    // weights (sized NUM_WITNESSES = 5 for basic-2).
    let _alphas_a: [Field; NUM_WITNESSES] = multiply_matrix_by_eq::<1, NUM_CONSTRAINTS, NUM_WITNESSES>(A_TRIPLES, eq_evals);
    let _alphas_b: [Field; NUM_WITNESSES] = multiply_matrix_by_eq::<1, NUM_CONSTRAINTS, NUM_WITNESSES>(B_TRIPLES, eq_evals);
    let _alphas_c: [Field; NUM_WITNESSES] = multiply_matrix_by_eq::<3, NUM_CONSTRAINTS, NUM_WITNESSES>(C_TRIPLES, eq_evals);
    // TODO(soundness): these `_alphas_*` are not yet consumed by the
    // (stubbed) inner WHIR LDT verifier; they will become the
    // `weight_refs_1` passed to `self.whir_witness.verify(...)` in the Rust
    // reference.

    // -------------------------------------------------------------------
    // Step 8: Absorb the prover's claimed A/B/C evaluations at alpha.
    // -------------------------------------------------------------------
    t.absorb_field(evals_az);
    t.absorb_field(evals_bz);
    t.absorb_field(evals_cz);

    // -------------------------------------------------------------------
    // Step 9: zkWHIR layer (witness-side blinded commitment).
    //
    // Mirrors `whir::protocols::whir_zk::verifier::verify` -- squeezes the
    // blinding/masking challenges, absorbs the prover hints, then delegates
    // to the inner witness-side and blinding-side WHIR low-degree-test
    // verifiers.
    // -------------------------------------------------------------------

    // 9a. Squeeze the blinding challenge.
    let _blinding_challenge: Field = t.squeeze_field();

    // 9b. Absorb the w_folded_blinding_evals vector (size 14 for basic-2).
    for i in 0..W_FOLDED_BLINDING_EVALS_LEN {
        t.absorb_field(w_folded_blinding_evals[i]);
    }

    // 9c. Squeeze the masking challenge. TODO(soundness): assert != 0.
    let _masking_challenge: Field = t.squeeze_field();

    // 9d. Receive the witness-side initial WHIR commitment.
    let witness_initial_commitment = Commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT> {
        root: witness_initial_root,
        ood_evals: witness_initial_ood_evals,
    };
    // ood_points discarded: in-domain consistency checks are stubbed (TODO(soundness)).
    let _ood_points_witness = receive_commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT>(&mut t, witness_initial_commitment);

    // 9e. Compute h_gammas (OOD points expanded into coset points).
    // TODO(soundness): real h_gammas come from `initial_in_domain.points`
    // which the (stubbed) inner WHIR LDT verifier would have returned. For
    // now, treat h_gammas as a single placeholder zero -- meaningless for
    // soundness, but lets the absorb sequence type-check.
    let _h_gammas: [Field; INITIAL_OOD_COUNT] = [0];

    // 9f. Squeeze tau1 and tau2 batching challenges.
    let _tau1: Field = t.squeeze_field();
    let _tau2: Field = t.squeeze_field();

    // 9g. Absorb per-gamma per-poly m_eval + g_hat_evals.
    // For basic-2: 8 gammas x 1 poly x (1 m_eval + 13 g_hat_evals each).
    // Order matches the Rust verifier: for each gamma, for each poly,
    // read 1 m_eval then 13 g_hat_evals.
    for gamma_idx in 0..8 {
        t.absorb_field(witness_m_evals[gamma_idx]);
        for j in 0..13 {
            t.absorb_field(witness_g_hat_evals[gamma_idx * 13 + j]);
        }
    }

    // 9h. Absorb combined_claims and batched_h_claims (size 1 each).
    for i in 0..1 {
        t.absorb_field(combined_claims[i]);
    }
    for i in 0..1 {
        t.absorb_field(batched_h_claims[i]);
    }

    // 9i. Inner WHIR LDT -- witness side (STUBBED).
    //
    // TODO(soundness): real verifier would do:
    //   for round in 0..NUM_WHIR_ROUNDS:
    //     - receive Merkle root + OOD evals  (real receive_commitment)
    //     - run inner sumcheck (INITIAL_SUMCHECK_ROUNDS rounds)
    //     - verify per-query Merkle openings (INITIAL_QUERY_COUNT queries)
    //     - verify in-domain consistency between round i and round i-1
    //     - verify PoW for this round's difficulty
    //   - run final sumcheck (FINAL_SUMCHECK_ROUNDS rounds)
    //   - absorb final polynomial
    //   - verify final PoW
    //   - verify final query Merkle openings on the last round
    //
    // We do JUST the transcript absorbs + PoW verifications so downstream
    // challenges stay consistent.
    for round in 0..NUM_WHIR_ROUNDS {
        // Absorb the round's Merkle root.
        t.absorb_field(whir_round_roots[round]);
        // Absorb OOD evals for the round.
        for i in 0..INITIAL_OOD_COUNT {
            t.absorb_field(whir_round_ood_evals[round][i]);
        }
        // Absorb the inner-sumcheck round polynomials.
        for s in 0..INITIAL_SUMCHECK_ROUNDS {
            for j in 0..SUMCHECK_POLY_COEFFS {
                t.absorb_field(whir_round_sumcheck_polys[round][s][j]);
            }
            // Squeeze the per-sumcheck-round challenge so transcript advances.
            let _alpha_s: Field = t.squeeze_field();
        }
        // Verify PoW for this round.
        // TODO(codegen): per-round PoW threshold should also come from codegen.
        let threshold = pow_threshold(round_pow_bits(round));
        verify_pow(&mut t, whir_round_pow_nonces[round], threshold);
    }

    // 9j. Final sumcheck rounds + final polynomial + final PoW.
    for s in 0..FINAL_SUMCHECK_ROUNDS {
        for j in 0..SUMCHECK_POLY_COEFFS {
            t.absorb_field(whir_final_sumcheck_polys[s][j]);
        }
        let _alpha_final: Field = t.squeeze_field();
    }
    for i in 0..2 {
        t.absorb_field(whir_final_polynomial[i]);
    }
    let final_threshold = pow_threshold(FINAL_POW_BITS);
    verify_pow(&mut t, whir_final_pow_nonce, final_threshold);

    // 9k. Inner WHIR LDT -- blinding side (STUBBED ENTIRELY).
    // TODO(soundness): real verifier runs a second WHIR LDT against
    // `commitment.blinding`. Skipped here.

    // -------------------------------------------------------------------
    // Step 10: Final Spartan equation.
    //
    //   assert f_at_alpha == (az * bz - cz) * eq(r, alpha)
    // -------------------------------------------------------------------
    let eq_r_alpha = calculate_eq::<M_0>(sumcheck_result.r, alpha);
    let rhs = (evals_az * evals_bz - evals_cz) * eq_r_alpha;
    assert(sumcheck_result.f_at_alpha == rhs);
}

/// Compute `2^(64 - difficulty_bits)` as a u64.
///
/// Matches `whir::protocols::proof_of_work::Config::threshold`.
fn pow_threshold(difficulty_bits: u32) -> u64 {
    // 2^(64 - difficulty_bits)
    let mut shift: u64 = 1;
    for _ in 0..(64 - difficulty_bits) {
        shift *= 2;
    }
    shift
}

/// Per-round PoW difficulty bits (basic-2 hardcoded).
fn round_pow_bits(round: u32) -> u32 {
    if round == 0 {
        ROUND_POW_BITS_0
    } else if round == 1 {
        ROUND_POW_BITS_1
    } else {
        ROUND_POW_BITS_2
    }
}
