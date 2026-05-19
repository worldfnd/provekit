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
    BLINDING_OOD_COUNT, BLINDING_OOD_POINTS, FINAL_POW_THRESHOLD, FINAL_SUMCHECK_ROUNDS,
    FINAL_VECTOR_LEN, INITIAL_OOD_COUNT, INITIAL_SUMCHECK_ROUNDS, M_0, NUM_CONSTRAINTS,
    NUM_WHIR_ROUNDS, NUM_WITNESSES, QUERY_BYTES_TOTAL_0, QUERY_BYTES_TOTAL_1, QUERY_BYTES_TOTAL_2,
    QUERY_BYTES_TOTAL_FINAL, ROUND_POW_THRESHOLD_0, ROUND_POW_THRESHOLD_1, ROUND_POW_THRESHOLD_2,
    SUMCHECK_POLY_COEFFS, W_FOLDED_BLINDING_EVALS_LEN,
};
use crate::whir::{
    inner_sumcheck_round, receive_commitment, stub_prev_commit_open, verify_pow, Commitment,
};

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

    // (Removed: phantom witness_initial_root/witness_initial_ood_evals. The
    // Rust verifier does NOT do a second receive_commitment here -- it calls
    // `initial_committer.verify` which only squeezes query-index bytes.)

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

    // --- WHIR inner-LDT prover messages ---
    //
    // For each WHIR round we receive (in transcript order):
    //   * Merkle root + INITIAL_OOD_COUNT OOD evals (receive_commitment)
    //   * PoW nonce for round_config.pow
    //   * INITIAL_SUMCHECK_ROUNDS quadratic-sumcheck round pairs (c0, c2),
    //     each round 2 Field elements
    //
    // The "previous-round Merkle opening" step is STUBBED: the verifier
    // squeezes QUERY_BYTES_TOTAL_k bytes from the transcript (matches
    // `challenge_indices`) but does not consume any narg fields here.

    // Initial-sumcheck polynomials (executed BEFORE the WHIR round loop in
    // the Rust verifier). INITIAL_SUMCHECK_ROUNDS rounds * 2 fields per round.
    initial_sumcheck_polys: [[Field; 2]; INITIAL_SUMCHECK_ROUNDS],

    // Per-WHIR-round inputs.
    whir_round_roots: [Field; NUM_WHIR_ROUNDS],
    whir_round_ood_evals: [[Field; INITIAL_OOD_COUNT]; NUM_WHIR_ROUNDS],
    whir_round_pow_nonces: [[u8; 8]; NUM_WHIR_ROUNDS],
    // 2 fields (c0, c2) per round-sumcheck round.
    whir_round_sumcheck_polys: [[[Field; 2]; INITIAL_SUMCHECK_ROUNDS]; NUM_WHIR_ROUNDS],

    // Final-round inputs:
    //   * FINAL_VECTOR_LEN field elements (`final_vector`)
    //   * final PoW nonce
    //   * FINAL_SUMCHECK_ROUNDS quadratic-sumcheck pairs (c0, c2)
    whir_final_vector: [Field; FINAL_VECTOR_LEN],
    whir_final_pow_nonce: [u8; 8],
    whir_final_sumcheck_polys: [[Field; 2]; FINAL_SUMCHECK_ROUNDS],
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

    // 9d. STUB `blinded_commitment.initial_committer.verify`. The Rust
    // verifier squeezes INITIAL_QUERY_COUNT (127) query indices, each
    // QUERY_BYTES_0 (2) bytes wide, and reads Merkle openings from `hints`
    // (no narg consumed). We squeeze the same 254 bytes here to keep the
    // transcript aligned; the Merkle path verification + in-domain
    // consistency checks are STUBBED.
    //
    // TODO(soundness): perform the actual Merkle path verification using the
    // `hints` proof stream and assert the in-domain row consistency.
    stub_prev_commit_open::<QUERY_BYTES_TOTAL_0>(&mut t);

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

    // 9i. Inner WHIR LDT -- witness side.
    //
    // Mirrors `whir::Config::verify` (basic-2 path):
    //   1. Build oods_matrix (single commitment, no cross-term reads).
    //   2. geometric_challenge(vector_rlc, num_vectors=1) -- NO squeeze.
    //   3. geometric_challenge(constraint_rlc, 1 + num_linear_forms=5) -- 1 squeeze.
    //   4. initial_sumcheck.verify: INITIAL_SUMCHECK_ROUNDS rounds of
    //      (absorb c0, absorb c2, squeeze alpha).
    //   5. For each round in 0..NUM_WHIR_ROUNDS:
    //      a. receive_commitment(this round) -- root + OOD evals.
    //      b. round_config.pow.verify -- real PoW check (squeeze 32 bytes,
    //         absorb 8-byte nonce).
    //      c. STUB the prev-commit Merkle open: squeeze QUERY_BYTES_TOTAL_k
    //         bytes (matches `challenge_indices`). No narg consumed.
    //      d. geometric_challenge(constraint_rlc, prev_in_domain + 1) -- 1 squeeze.
    //      e. sumcheck (3 rounds): per round absorb (c0, c2), squeeze alpha.
    //   6. Final round:
    //      a. Absorb FINAL_VECTOR_LEN fields (final_vector).
    //      b. final_pow.verify -- real PoW check.
    //      c. STUB the prev-commit (round_configs.last()) open: squeeze
    //         QUERY_BYTES_TOTAL_FINAL bytes.
    //      d. STUB in-domain consistency assert.
    //      e. final_sumcheck (FINAL_SUMCHECK_ROUNDS rounds): per round absorb
    //         (c0, c2), squeeze alpha.

    // Step 3: constraint_rlc squeeze.
    // `oods_evals.len()` = `initial_committer.out_domain_samples` * num_vectors
    //   = 1 (for basic-2). `num_linear_forms` = evaluations.len() / num_vectors
    //   = 4 (alpha_A, alpha_B, alpha_C, blinding). Total count = 5.
    // For count > 1, geometric_challenge squeezes 1 field.
    let _constraint_rlc_initial: Field = t.squeeze_field();

    // Step 4: initial_sumcheck.verify (3 rounds for basic-2).
    for s in 0..INITIAL_SUMCHECK_ROUNDS {
        let c0 = initial_sumcheck_polys[s][0];
        let c2 = initial_sumcheck_polys[s][1];
        let _alpha = inner_sumcheck_round(&mut t, c0, c2);
    }

    // Step 5: WHIR rounds (NUM_WHIR_ROUNDS = 3 for basic-2).
    // TODO(generalize): unroll-by-hand because Noir cannot dispatch on a
    // runtime-known round index for the differently-sized QUERY_BYTES_TOTAL_k
    // generics.
    if NUM_WHIR_ROUNDS >= 1 {
        whir_round_step::<0, QUERY_BYTES_TOTAL_0>(
            &mut t,
            whir_round_roots[0],
            whir_round_ood_evals[0],
            whir_round_pow_nonces[0],
            whir_round_sumcheck_polys[0],
            ROUND_POW_THRESHOLD_0,
        );
    }
    if NUM_WHIR_ROUNDS >= 2 {
        whir_round_step::<1, QUERY_BYTES_TOTAL_1>(
            &mut t,
            whir_round_roots[1],
            whir_round_ood_evals[1],
            whir_round_pow_nonces[1],
            whir_round_sumcheck_polys[1],
            ROUND_POW_THRESHOLD_1,
        );
    }
    if NUM_WHIR_ROUNDS >= 3 {
        whir_round_step::<2, QUERY_BYTES_TOTAL_2>(
            &mut t,
            whir_round_roots[2],
            whir_round_ood_evals[2],
            whir_round_pow_nonces[2],
            whir_round_sumcheck_polys[2],
            ROUND_POW_THRESHOLD_2,
        );
    }

    // Step 6: Final round.
    // 6a. Absorb final_vector.
    for i in 0..FINAL_VECTOR_LEN {
        t.absorb_field(whir_final_vector[i]);
    }
    // 6b. Final PoW.
    verify_pow(&mut t, whir_final_pow_nonce, FINAL_POW_THRESHOLD);
    // 6c. STUB the last-round Merkle open: squeeze QUERY_BYTES_TOTAL_FINAL bytes.
    stub_prev_commit_open::<QUERY_BYTES_TOTAL_FINAL>(&mut t);
    // 6d. STUB in-domain consistency assert.
    // TODO(soundness): assert `weights.evaluate(&Identity, final_vector) == evals`
    //   for each (weights, evals) in the round_configs.last() in_domain pairs.
    // 6e. Constraint RLC for the final round (count = prev_round.in_domain + 1).
    // For final round following round_configs.last(): squeeze 1 field if count > 1.
    let _final_constraint_rlc: Field = t.squeeze_field();
    // 6f. final_sumcheck.verify: FINAL_SUMCHECK_ROUNDS rounds.
    for s in 0..FINAL_SUMCHECK_ROUNDS {
        let c0 = whir_final_sumcheck_polys[s][0];
        let c2 = whir_final_sumcheck_polys[s][1];
        let _alpha = inner_sumcheck_round(&mut t, c0, c2);
    }

    // 9k. Inner WHIR LDT -- blinding side (STUBBED ENTIRELY).
    // TODO(soundness): real verifier runs a second WHIR LDT against
    // `commitment.blinding`. Skipped here -- nargo execute will stop somewhere
    // in this blinding-side flow.

    // -------------------------------------------------------------------
    // Step 10: Final Spartan equation.
    //
    //   assert f_at_alpha == (az * bz - cz) * eq(r, alpha)
    // -------------------------------------------------------------------
    let eq_r_alpha = calculate_eq::<M_0>(sumcheck_result.r, alpha);
    let rhs = (evals_az * evals_bz - evals_cz) * eq_r_alpha;
    assert(sumcheck_result.f_at_alpha == rhs);
}

// PoW thresholds are now emitted directly as `u64` constants from the
// codegen (ROUND_POW_THRESHOLD_k, FINAL_POW_THRESHOLD) so the verifier
// matches the Rust `proof_of_work::threshold(difficulty)` exactly,
// including fractional-bit difficulties.

/// One iteration of the WHIR LDT round loop, parameterised by the previous
/// round's QUERY_BYTES_TOTAL (which differs per round).
///
/// Sequence:
///   1. receive_commitment(this round): absorb root, squeeze OOD points,
///      absorb OOD evals.
///   2. PoW.verify: squeeze 32 bytes, absorb 8-byte nonce.
///   3. STUB the open-prev-commit step: squeeze QUERY_BYTES bytes (matches
///      `challenge_indices` for the previous round's in-domain samples).
///   4. constraint_rlc squeeze (1 field; count is always > 1 for basic-2).
///   5. Sumcheck (INITIAL_SUMCHECK_ROUNDS rounds): per round absorb (c0, c2),
///      squeeze alpha. NO PoW (round_pow=none for basic-2). NO consistency
///      check (in-domain values stubbed, so saved == c0 + c1 cannot be
///      computed without the real prev-round folded vector).
fn whir_round_step<let ROUND: u32, let QUERY_BYTES: u32>(
    t: &mut Transcript,
    root: Field,
    ood_evals: [Field; INITIAL_OOD_COUNT],
    pow_nonce: [u8; 8],
    sumcheck_polys: [[Field; 2]; INITIAL_SUMCHECK_ROUNDS],
    pow_threshold: u64,
) {
    let _ = ROUND; // ROUND is for clarity / future shape checks.

    // 1. receive_commitment(this round).
    let commit = Commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT> {
        root,
        ood_evals,
    };
    let _ood_points = receive_commitment::<INITIAL_OOD_COUNT, INITIAL_OOD_COUNT>(t, commit);

    // 2. round-level PoW.
    verify_pow(t, pow_nonce, pow_threshold);

    // 3. STUB the open-prev-commit Merkle verify, squeezing the query-index
    //    bytes the Rust verifier would consume.
    stub_prev_commit_open::<QUERY_BYTES>(t);

    // 4. constraint_rlc squeeze.
    // For basic-2 every WHIR round's constraint_values.len() > 1 (e.g.
    // 1 OOD + prev_in_domain_samples), so geometric_challenge squeezes 1 field.
    let _constraint_rlc: Field = t.squeeze_field();

    // 5. Sumcheck rounds (no PoW for basic-2; no consistency check).
    for s in 0..INITIAL_SUMCHECK_ROUNDS {
        let c0 = sumcheck_polys[s][0];
        let c2 = sumcheck_polys[s][1];
        let _alpha = inner_sumcheck_round(t, c0, c2);
    }
}
