// ProveKit Recursive Verifier -- Entry Point
//
// This Noir circuit verifies a ProveKit WHIR+Spartan proof.
//
// The verification flow mirrors provekit/verifier/src/whir_r1cs.rs and
// the WHIR library's whir_zk::verify + whir::Config::verify.
//
// Protocol phases:
//   0. Initialize Fiat-Shamir transcript (Poseidon2 duplex sponge)
//   1. Receive commitments (f_hat + blinding)
//   2. Run Spartan sumcheck
//   3. Verify public input binding (Poseidon2 length-IV sponge hash + geometric eval)
//   4. zkWHIR verification (blinding challenge, inner WHIR, per-gamma claims)
//   5. Evaluate R1CS matrix extensions
//   6. Final Spartan relation check: f_at_alpha == (az*bz - cz) * EQ(r, alpha)
//
// All inputs are pre-parsed by a Rust-side tool (generate_noir_verifier_inputs).

mod types;
mod transcript;
mod sumcheck;
mod merkle;
mod matrix_eval;
mod public_input;
mod whir;

use matrix_eval::{calculate_eq, eq_over_hypercube, evaluate_r1cs_matrices};
use merkle::verify_merkle_proof_dynamic;
use public_input::{verify_public_eval, verify_public_input_hash};
use sumcheck::{run_sumcheck_verifier, SumcheckResult};
use transcript::Sponge;
use types::{
    BLINDING_FINAL_POLY_ARRAY_SIZE, BLINDING_FINAL_POLY_SIZE, BLINDING_FINAL_SC_ARRAY_SIZE,
    BLINDING_FINAL_SUMCHECK_ROUNDS, BLINDING_FOLD_SIZE, BLINDING_INITIAL_OOD_COUNT,
    BLINDING_MAX_QUERIES, BLINDING_MERKLE_LEAF_SIZE, BLINDING_OOD_SAMPLES, BLINDING_ROUND_ARRAY_SIZE,
    BLINDING_STIR_BYTES_PER_INDEX, BLINDING_TREE_HEIGHT, BLINDING_WHIR_CONSTRAINT_COUNT,
    BLINDING_WHIR_ROUNDS, FINAL_POLY_SIZE, FINAL_SC_ARRAY_SIZE, FINAL_SUMCHECK_ROUNDS, FOLD_SIZE,
    FOLDING_FACTOR, INITIAL_OOD_COUNT, INNER_WHIR_CONSTRAINT_COUNT, LOG_NUM_CONSTRAINTS,
    LOG_NUM_VARIABLES, MatrixCell, MAX_GAMMAS, MAX_MATRIX_CELLS, MAX_PUBLIC_INPUTS,
    MAX_QUERIES_PER_ROUND, NUM_BLINDING_VECTORS, NUM_W_FOLDED_EVALS, NUM_WHIR_ROUNDS,
    NUM_WITNESS_VARIABLES, OOD_SAMPLES, ROUND_ARRAY_SIZE, STIR_BYTES_PER_INDEX, TREE_HEIGHT,
};
use whir::{
    check_pow, compute_fold, generate_combination_randomness, run_whir_sumcheck,
    squeeze_stir_challenges,
};

// --- Compile-time sizes ---

global EQ_ROW_SIZE: u32 = 1 << LOG_NUM_CONSTRAINTS;
global EQ_COL_SIZE: u32 = 1 << LOG_NUM_VARIABLES;

global PROTOCOL_ID_SIZE: u32 = 64;
global INSTANCE_SIZE: u32 = 32;

// Public inputs: when MAX_PUBLIC_INPUTS=0, keep a sized array at 1.
global PUBLIC_INPUTS_ARRAY_SIZE: u32 = if MAX_PUBLIC_INPUTS == 0 {
    1
} else {
    MAX_PUBLIC_INPUTS
};

// --- Entry point ---

fn main(
    // --- Transcript initialization ---
    protocol_id: [u8; PROTOCOL_ID_SIZE],
    instance: [u8; INSTANCE_SIZE],
    // --- Phase 1: Commitment data ---
    initial_root_hash: Field,
    initial_ood_answers: [Field; INITIAL_OOD_COUNT],
    blinding_root_hash: Field,
    blinding_ood_answers: [Field; BLINDING_INITIAL_OOD_COUNT],
    // --- Phase 2: Spartan sumcheck prover messages ---
    sum_g: Field,
    sumcheck_coeffs: [[Field; 4]; LOG_NUM_CONSTRAINTS],
    blinding_eval: Field,
    // --- Phase 3: Public inputs ---
    public_inputs: pub [Field; PUBLIC_INPUTS_ARRAY_SIZE],
    num_public_inputs: pub u32,
    public_inputs_hash_from_prover: Field,
    // --- Phase 3b: Evaluation claims ---
    evals_az: Field,
    evals_bz: Field,
    evals_cz: Field,
    public_eval: Field,
    // --- Phase 4: zkWHIR verification data ---
    w_folded_evals: [Field; NUM_W_FOLDED_EVALS],
    // --- Phase 4a: Inner WHIR verify (blinded_commitment) ---
    // WHIR sumcheck coefficients: [c0, c2] per round (c1 derived as sum - 2*c0 - c2)
    initial_whir_sumcheck_coeffs: [[Field; 2]; FOLDING_FACTOR],
    // Per-round WHIR data (uses ROUND_ARRAY_SIZE = max(NUM_WHIR_ROUNDS, 1))
    round_root_hashes: [Field; ROUND_ARRAY_SIZE],
    round_ood_answers: [[Field; OOD_SAMPLES]; ROUND_ARRAY_SIZE],
    round_whir_sumcheck_coeffs: [[[Field; 2]; FOLDING_FACTOR]; ROUND_ARRAY_SIZE],
    round_merkle_leaves: [[[Field; FOLD_SIZE]; MAX_QUERIES_PER_ROUND]; ROUND_ARRAY_SIZE],
    round_merkle_siblings: [[[Field; TREE_HEIGHT]; MAX_QUERIES_PER_ROUND]; ROUND_ARRAY_SIZE],
    round_merkle_indices: [[u32; MAX_QUERIES_PER_ROUND]; ROUND_ARRAY_SIZE],
    round_merkle_leaf_sizes: [u32; ROUND_ARRAY_SIZE],
    round_merkle_tree_heights: [u32; ROUND_ARRAY_SIZE],
    round_num_queries: [u32; ROUND_ARRAY_SIZE],
    round_pow_nonces: [u64; ROUND_ARRAY_SIZE],
    // Final WHIR round data (blinded commitment)
    final_coefficients: [Field; FINAL_POLY_SIZE],
    final_pow_nonce: u64,
    final_merkle_leaves: [[Field; FOLD_SIZE]; MAX_QUERIES_PER_ROUND],
    final_merkle_siblings: [[Field; TREE_HEIGHT]; MAX_QUERIES_PER_ROUND],
    final_merkle_indices: [u32; MAX_QUERIES_PER_ROUND],
    final_merkle_leaf_size: u32,
    final_merkle_tree_height: u32,
    final_num_queries: u32,
    // Final sumcheck (FINAL_SUMCHECK_ROUNDS rounds)
    final_whir_sumcheck_coeffs: [[Field; 2]; FINAL_SC_ARRAY_SIZE],
    // --- Phase 4b: Per-gamma claims ---
    num_gammas: u32,
    gamma_m_evals: [Field; MAX_GAMMAS],
    gamma_g_hat_evals: [[Field; NUM_WITNESS_VARIABLES]; MAX_GAMMAS],
    combined_claims: Field,
    batched_h_claims: Field,
    // --- Phase 4c: Blinding WHIR verification ---
    blinding_whir_initial_coeffs: [[Field; 2]; FOLDING_FACTOR],
    blinding_round_root_hashes: [Field; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_ood_answers: [[Field; BLINDING_OOD_SAMPLES]; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_sumcheck_coeffs: [[[Field; 2]; FOLDING_FACTOR]; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_merkle_leaves: [[[Field; BLINDING_MERKLE_LEAF_SIZE]; BLINDING_MAX_QUERIES]; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_merkle_siblings: [[[Field; BLINDING_TREE_HEIGHT]; BLINDING_MAX_QUERIES]; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_merkle_indices: [[u32; BLINDING_MAX_QUERIES]; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_merkle_leaf_sizes: [u32; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_merkle_tree_heights: [u32; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_num_queries: [u32; BLINDING_ROUND_ARRAY_SIZE],
    blinding_round_pow_nonces: [u64; BLINDING_ROUND_ARRAY_SIZE],
    blinding_final_coefficients: [Field; BLINDING_FINAL_POLY_ARRAY_SIZE],
    blinding_final_pow_nonce: u64,
    blinding_final_sumcheck_coeffs: [[Field; 2]; BLINDING_FINAL_SC_ARRAY_SIZE],
    blinding_final_merkle_leaves: [[Field; BLINDING_MERKLE_LEAF_SIZE]; BLINDING_MAX_QUERIES],
    blinding_final_merkle_siblings: [[Field; BLINDING_TREE_HEIGHT]; BLINDING_MAX_QUERIES],
    blinding_final_merkle_indices: [u32; BLINDING_MAX_QUERIES],
    blinding_final_merkle_leaf_size: u32,
    blinding_final_merkle_tree_height: u32,
    blinding_final_num_queries: u32,
    // --- Phase 5: R1CS matrices (sparse, flattened) ---
    matrix_a_rows: [u32; MAX_MATRIX_CELLS],
    matrix_a_cols: [u32; MAX_MATRIX_CELLS],
    matrix_a_vals: [Field; MAX_MATRIX_CELLS],
    a_len: u32,
    matrix_b_rows: [u32; MAX_MATRIX_CELLS],
    matrix_b_cols: [u32; MAX_MATRIX_CELLS],
    matrix_b_vals: [Field; MAX_MATRIX_CELLS],
    b_len: u32,
    matrix_c_rows: [u32; MAX_MATRIX_CELLS],
    matrix_c_cols: [u32; MAX_MATRIX_CELLS],
    matrix_c_vals: [Field; MAX_MATRIX_CELLS],
    c_len: u32,
) {
    // ===================================================================
    // Phase 0: Initialize Fiat-Shamir transcript
    // ===================================================================

    let mut sho = Sponge::new();
    sho.absorb_bytes(protocol_id);
    sho.absorb_bytes(instance);

    // ===================================================================
    // Phase 1: Receive commitments
    // ===================================================================
    //
    // irs_commit::receive_commitment -> absorb Merkle root + squeeze/absorb OOD

    // Phase 1a: f_hat commitment (blinded_commitment)
    // OOD points: one per OOD sample (verifier_message_vec(out_domain_samples))
    // OOD answers: out_domain_samples * num_vectors prover messages -- matches
    // whir::protocols::irs_commit::receive_commitment.
    sho.absorb_field_aligned(initial_root_hash);

    for _i in 0..OOD_SAMPLES {
        let _ood_query = sho.squeeze_field_aligned();
    }
    for i in 0..INITIAL_OOD_COUNT {
        sho.absorb_field_aligned(initial_ood_answers[i]);
    }

    // Phase 1b: Blinding commitment (num_vectors = NUM_BLINDING_VECTORS, so
    // there are BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS OOD answers).
    sho.absorb_field_aligned(blinding_root_hash);

    for _i in 0..BLINDING_OOD_SAMPLES {
        let _blinding_ood_query = sho.squeeze_field_aligned();
    }
    for i in 0..BLINDING_INITIAL_OOD_COUNT {
        sho.absorb_field_aligned(blinding_ood_answers[i]);
    }

    // ===================================================================
    // Phase 2: Run Spartan sumcheck
    // ===================================================================

    let sc_result: SumcheckResult<LOG_NUM_CONSTRAINTS> =
        run_sumcheck_verifier(&mut sho, sumcheck_coeffs, sum_g, blinding_eval);

    // ===================================================================
    // Phase 3: Public input binding + evaluation claims
    // ===================================================================

    sho.absorb_field(public_inputs_hash_from_prover);

    verify_public_input_hash(
        public_inputs_hash_from_prover,
        public_inputs,
        num_public_inputs,
    );

    let x: Field = sho.squeeze_field();

    sho.absorb_field(evals_az);
    sho.absorb_field(evals_bz);
    sho.absorb_field(evals_cz);

    if num_public_inputs > 0 {
        sho.absorb_field(public_eval);
        verify_public_eval(public_eval, x, public_inputs, num_public_inputs);
    }

    // ===================================================================
    // Phase 4: zkWHIR verification (whir_zk::Config::verify)
    // ===================================================================

    // 4.1: blinding_challenge (verifier_message)
    let _beta: Field = sho.squeeze_field();

    // 4.2: w_folded_blinding_evals (prover_messages_vec)
    for i in 0..NUM_W_FOLDED_EVALS {
        sho.absorb_field(w_folded_evals[i]);
    }

    // 4.3: masking_challenge (verifier_message)
    let masking_challenge: Field = sho.squeeze_field();
    assert(masking_challenge != 0, "masking_challenge must be non-zero");

    // 4.4: STIR opening of initial blinded commitment (irs_commit::verify)
    // The zkWHIR verifier opens the initial commitment to get in-domain
    // points for gamma computation. This squeezes STIR_TOTAL_BYTES bytes.
    squeeze_stir_challenges(&mut sho, MAX_QUERIES_PER_ROUND, STIR_BYTES_PER_INDEX);

    // 4.5: tau1 (verifier_message)
    let _tau1: Field = sho.squeeze_field();

    // 4.6: tau2 (verifier_message)
    let _tau2: Field = sho.squeeze_field();

    // 4.7: Per-gamma prover messages
    // For each gamma point (from the STIR opening), for each polynomial:
    //   absorb m_eval, then g_hat_eval per witness variable
    for g in 0..MAX_GAMMAS {
        if (g as u32) < num_gammas {
            sho.absorb_field(gamma_m_evals[g]);
            for v in 0..NUM_WITNESS_VARIABLES {
                sho.absorb_field(gamma_g_hat_evals[g][v]);
            }
        }
    }

    // 4.8: combined_claims (prover_messages_vec, 1 per polynomial)
    sho.absorb_field(combined_claims);

    // 4.9: batched_h_claims (prover_messages_vec, 1 per polynomial)
    sho.absorb_field(batched_h_claims);

    // ===================================================================
    // Phase 4a: Inner WHIR verify (blinded_commitment: whir::Config::verify)
    // ===================================================================
    //
    // Protocol flow for NUM_WHIR_ROUNDS=0:
    //   1. OOD cross-terms: none for single commitment, single vector
    //   2. geometric_challenge(num_vectors=1) -> no-op
    //   3. geometric_challenge(INNER_WHIR_CONSTRAINT_COUNT) -> squeeze if >= 2
    //   4. Initial sumcheck (FOLDING_FACTOR rounds, quadratic)
    //   5. Final vector (prover_messages_vec)
    //   6. Final PoW
    //   7. STIR opening of initial commitment (squeeze bytes)
    //   8. Verify in-domain constraints
    //   9. Final sumcheck (FINAL_SUMCHECK_ROUNDS rounds)

    // 4a.1: geometric_challenge(num_vectors=1) -> returns [1], no transcript ops
    let _vector_rlc: [Field; 1] = generate_combination_randomness(&mut sho, 1);

    // 4a.2: geometric_challenge(INNER_WHIR_CONSTRAINT_COUNT)
    // count = OOD_SAMPLES + NUM_LINEAR_FORMS (e.g. 1 + 5 = 6)
    let _constraint_rlc: [Field; INNER_WHIR_CONSTRAINT_COUNT] =
        generate_combination_randomness(&mut sho, INNER_WHIR_CONSTRAINT_COUNT);

    // Accumulator for all folding randomness across sumcheck phases (total = m)
    let mut total_folding_rand: [Field; LOG_NUM_VARIABLES] = [0; LOG_NUM_VARIABLES];

    // 4a.3: Initial WHIR sumcheck (FOLDING_FACTOR rounds, quadratic)
    let (initial_fold_rand, mut last_eval) =
        run_whir_sumcheck(&mut sho, 0, initial_whir_sumcheck_coeffs);

    // Store initial folding randomness
    for i in 0..FOLDING_FACTOR {
        total_folding_rand[i] = initial_fold_rand[i];
    }

    // 4a.4: Per-round WHIR verification (for NUM_WHIR_ROUNDS > 0)
    for r in 0..NUM_WHIR_ROUNDS {
        // Receive round commitment (irs_commit::receive_commitment)
        sho.absorb_field(round_root_hashes[r]);

        for _i in 0..OOD_SAMPLES {
            let _ood_pt = sho.squeeze_field();
        }
        for i in 0..OOD_SAMPLES {
            sho.absorb_field(round_ood_answers[r][i]);
        }

        // Between-round PoW (whir/verifier.rs: round_config.pow.verify)
        check_pow(&mut sho, round_pow_nonces[r]);

        // Open previous commitment: STIR challenge indices (squeeze bytes)
        squeeze_stir_challenges(&mut sho, round_num_queries[r], STIR_BYTES_PER_INDEX);

        // Verify Merkle proofs for the opening
        let n_queries = round_num_queries[r];
        for q in 0..MAX_QUERIES_PER_ROUND {
            if (q as u32) < n_queries {
                verify_merkle_proof_dynamic(
                    round_merkle_leaves[r][q],
                    round_merkle_leaf_sizes[r],
                    round_merkle_siblings[r][q],
                    round_merkle_tree_heights[r],
                    round_merkle_indices[r][q],
                    round_root_hashes[r],
                );
            }
        }

        // Compute fold from leaf values
        let _fold = compute_fold(round_merkle_leaves[r], initial_fold_rand, n_queries);

        // Constraint RLC for this round (geometric_challenge)
        let _round_constraint_rlc: Field = sho.squeeze_field();

        // Round sumcheck (quadratic, with potential per-round PoW inside)
        let (round_fold_rand, new_last_eval) =
            run_whir_sumcheck(&mut sho, last_eval, round_whir_sumcheck_coeffs[r]);
        last_eval = new_last_eval;

        // Accumulate round folding randomness
        let offset = FOLDING_FACTOR + (r as u32) * FOLDING_FACTOR;
        for i in 0..FOLDING_FACTOR {
            total_folding_rand[offset + i] = round_fold_rand[i];
        }
    }

    // 4a.5: Final vector (prover_messages_vec) -- FINAL_POLY_SIZE=2
    for i in 0..FINAL_POLY_SIZE {
        sho.absorb_field(final_coefficients[i]);
    }

    // 4a.6: Final PoW
    check_pow(&mut sho, final_pow_nonce);

    // 4a.7: STIR opening of initial/last commitment (squeeze bytes, NOT fields)
    squeeze_stir_challenges(&mut sho, final_num_queries, STIR_BYTES_PER_INDEX);

    // Verify final Merkle proofs:
    // - if no middle rounds, final opening is against initial_root_hash
    // - otherwise against the last round root
    let final_root = if NUM_WHIR_ROUNDS == 0 {
        initial_root_hash
    } else {
        round_root_hashes[NUM_WHIR_ROUNDS - 1]
    };
    for q in 0..MAX_QUERIES_PER_ROUND {
        if (q as u32) < final_num_queries {
            verify_merkle_proof_dynamic(
                final_merkle_leaves[q],
                final_merkle_leaf_size,
                final_merkle_siblings[q],
                final_merkle_tree_height,
                final_merkle_indices[q],
                final_root,
            );
        }
    }

    // 4a.8: Final sumcheck (FINAL_SUMCHECK_ROUNDS rounds)
    let (final_fold_rand, _final_last_eval) =
        run_whir_sumcheck(&mut sho, last_eval, final_whir_sumcheck_coeffs);

    // Accumulate final folding randomness
    let final_offset = FOLDING_FACTOR + NUM_WHIR_ROUNDS * FOLDING_FACTOR;
    for i in 0..FINAL_SUMCHECK_ROUNDS {
        total_folding_rand[final_offset + i] = final_fold_rand[i];
    }

    // ===================================================================
    // Phase 4b: Blinding WHIR verify (blinding_commitment: whir::Config::verify)
    // ===================================================================
    //
    // Same structure as inner WHIR but with blinding parameters.

    // geometric_challenge(blinding_num_vectors)
    let blinding_vector_rlc: [Field; NUM_BLINDING_VECTORS] =
        generate_combination_randomness(&mut sho, NUM_BLINDING_VECTORS);

    // geometric_challenge for blinding constraints
    let _blinding_constraint_rlc: [Field; BLINDING_WHIR_CONSTRAINT_COUNT] =
        generate_combination_randomness(&mut sho, BLINDING_WHIR_CONSTRAINT_COUNT);

    // Blinding initial sumcheck
    let (blinding_initial_fold_rand, mut blinding_last_eval) =
        run_whir_sumcheck(&mut sho, 0, blinding_whir_initial_coeffs);

    // Per-round blinding WHIR verification
    for r in 0..BLINDING_WHIR_ROUNDS {
        sho.absorb_field(blinding_round_root_hashes[r]);

        for _i in 0..BLINDING_OOD_SAMPLES {
            let _ood_pt = sho.squeeze_field();
        }
        for i in 0..BLINDING_OOD_SAMPLES {
            sho.absorb_field(blinding_round_ood_answers[r][i]);
        }

        check_pow(&mut sho, blinding_round_pow_nonces[r]);

        // STIR opening of previous blinding commitment
        squeeze_stir_challenges(
            &mut sho,
            blinding_round_num_queries[r],
            BLINDING_STIR_BYTES_PER_INDEX,
        );

        let n_queries = blinding_round_num_queries[r];
        for q in 0..BLINDING_MAX_QUERIES {
            if (q as u32) < n_queries {
                verify_merkle_proof_dynamic(
                    blinding_round_merkle_leaves[r][q],
                    blinding_round_merkle_leaf_sizes[r],
                    blinding_round_merkle_siblings[r][q],
                    blinding_round_merkle_tree_heights[r],
                    blinding_round_merkle_indices[r][q],
                    blinding_round_root_hashes[r],
                );
            }
        }

        // Reduce full Merkle rows (num_vectors * fold_size) into fold_size rows
        // using the same vector RLC as the Rust verifier.
        let mut blinding_fold_leaves: [[Field; BLINDING_FOLD_SIZE]; BLINDING_MAX_QUERIES] =
            [[0; BLINDING_FOLD_SIZE]; BLINDING_MAX_QUERIES];
        for q in 0..BLINDING_MAX_QUERIES {
            if (q as u32) < n_queries {
                for j in 0..BLINDING_FOLD_SIZE {
                    let mut acc: Field = 0;
                    for v in 0..NUM_BLINDING_VECTORS {
                        let idx = v * BLINDING_FOLD_SIZE + j;
                        acc += blinding_vector_rlc[v] * blinding_round_merkle_leaves[r][q][idx];
                    }
                    blinding_fold_leaves[q][j] = acc;
                }
            }
        }
        let _blinding_fold =
            compute_fold(blinding_fold_leaves, blinding_initial_fold_rand, n_queries);

        let _blinding_round_rlc: Field = sho.squeeze_field();

        let (_new_fold_rand, new_last_eval) = run_whir_sumcheck(
            &mut sho,
            blinding_last_eval,
            blinding_round_sumcheck_coeffs[r],
        );
        blinding_last_eval = new_last_eval;
        // Note: blinding_initial_fold_rand is not overwritten here;
        // for multi-round, we'd need to track all fold rands.
    }

    // Final blinding WHIR round
    for i in 0..BLINDING_FINAL_POLY_SIZE {
        sho.absorb_field(blinding_final_coefficients[i]);
    }
    check_pow(&mut sho, blinding_final_pow_nonce);

    // STIR opening for blinding final round
    squeeze_stir_challenges(
        &mut sho,
        blinding_final_num_queries,
        BLINDING_STIR_BYTES_PER_INDEX,
    );

    // Verify blinding final Merkle proofs against last round root (or initial if 0 rounds)
    let blinding_final_root = if BLINDING_WHIR_ROUNDS == 0 {
        blinding_root_hash
    } else {
        blinding_round_root_hashes[BLINDING_WHIR_ROUNDS - 1]
    };
    for q in 0..BLINDING_MAX_QUERIES {
        if (q as u32) < blinding_final_num_queries {
            verify_merkle_proof_dynamic(
                blinding_final_merkle_leaves[q],
                blinding_final_merkle_leaf_size,
                blinding_final_merkle_siblings[q],
                blinding_final_merkle_tree_height,
                blinding_final_merkle_indices[q],
                blinding_final_root,
            );
        }
    }

    // Blinding final sumcheck: BLINDING_FINAL_SUMCHECK_ROUNDS=0 means no rounds.
    // The array is sized BLINDING_FINAL_SC_ARRAY_SIZE=1 for Noir, but we skip execution.
    if BLINDING_FINAL_SUMCHECK_ROUNDS > 0 {
        let (_blinding_final_fold, _blinding_final_eval) =
            run_whir_sumcheck(&mut sho, blinding_last_eval, blinding_final_sumcheck_coeffs);
    }

    // ===================================================================
    // Phase 5: Evaluate R1CS matrix extensions
    // ===================================================================

    let eq_row: [Field; EQ_ROW_SIZE] = eq_over_hypercube(sc_result.alpha);
    let eq_col: [Field; EQ_COL_SIZE] = eq_over_hypercube(total_folding_rand);

    let mut matrix_a: [MatrixCell; MAX_MATRIX_CELLS] =
        [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    let mut matrix_b: [MatrixCell; MAX_MATRIX_CELLS] =
        [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    let mut matrix_c: [MatrixCell; MAX_MATRIX_CELLS] =
        [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    for i in 0..MAX_MATRIX_CELLS {
        matrix_a[i] =
            MatrixCell { row: matrix_a_rows[i], col: matrix_a_cols[i], val: matrix_a_vals[i] };
        matrix_b[i] =
            MatrixCell { row: matrix_b_rows[i], col: matrix_b_cols[i], val: matrix_b_vals[i] };
        matrix_c[i] =
            MatrixCell { row: matrix_c_rows[i], col: matrix_c_cols[i], val: matrix_c_vals[i] };
    }

    let matrix_evals: [Field; 3] = evaluate_r1cs_matrices(
        matrix_a,
        a_len,
        matrix_b,
        b_len,
        matrix_c,
        c_len,
        eq_row,
        eq_col,
    );

    assert(matrix_evals[0] == evals_az, "Matrix A evaluation mismatch");
    assert(matrix_evals[1] == evals_bz, "Matrix B evaluation mismatch");
    assert(matrix_evals[2] == evals_cz, "Matrix C evaluation mismatch");

    // ===================================================================
    // Phase 6: Final Spartan relation check
    // ===================================================================

    let eq_val = calculate_eq(sc_result.r, sc_result.alpha);
    let expected = (evals_az * evals_bz - evals_cz) * eq_val;
    assert(sc_result.f_at_alpha == expected, "Final Spartan relation check failed");
}
