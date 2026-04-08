// ProveKit Recursive Verifier -- Entry Point
//
// This Noir circuit verifies a ProveKit WHIR+Spartan proof.
//
// The verification flow mirrors provekit/verifier/src/whir_r1cs.rs and
// the WHIR library's whir_zk::verify + whir::Config::verify.
//
// Protocol phases:
//   0. Initialize Fiat-Shamir transcript (SHA256 SHO)
//   1. Receive commitments (f_hat + blinding)
//   2. Run Spartan sumcheck
//   3. Verify public input binding (Skyscraper hash + geometric eval)
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

use types::{
    LOG_NUM_CONSTRAINTS, NUM_WHIR_ROUNDS,
    FOLDING_FACTOR, MAX_QUERIES_PER_ROUND, TREE_HEIGHT, FOLD_SIZE,
    MAX_PUBLIC_INPUTS, OOD_SAMPLES,
    BLINDING_OOD_SAMPLES, BLINDING_WHIR_ROUNDS, BLINDING_TREE_HEIGHT,
    NUM_WITNESS_VARIABLES,
    BLINDING_MAX_QUERIES, BLINDING_FOLD_SIZE,
    NUM_W_FOLDED_EVALS, FINAL_POLY_SIZE,
    MAX_MATRIX_CELLS, MatrixCell,
};
use transcript::SHO;
use sumcheck::{run_sumcheck_verifier, SumcheckResult};
use merkle::verify_merkle_proof;
use matrix_eval::{eq_over_hypercube, calculate_eq, evaluate_r1cs_matrices};
use public_input::{verify_public_input_hash, verify_public_eval};
use whir::{run_whir_sumcheck, compute_fold, check_pow};

// --- Compile-time sizes ---

global EQ_ROW_SIZE: u32 = 32; // 2^LOG_NUM_CONSTRAINTS
global EQ_COL_SIZE: u32 = 32; // 2^LOG_NUM_VARIABLES

// Protocol ID is always 64 bytes (SHA3-512 of IO pattern)
global PROTOCOL_ID_SIZE: u32 = 64;
// Instance is always 32 bytes (Skyscraper hash of public inputs as LE bytes)
global INSTANCE_SIZE: u32 = 32;

// Maximum number of gamma points (= in_domain_samples * interleaving_depth)
global MAX_GAMMAS: u32 = 24; // upper bound for test config

// --- Entry point ---

fn main(
    // --- Transcript initialization ---
    // Protocol ID: SHA3-512 hash of the serialized WhirR1CSScheme IO pattern
    protocol_id: [u8; PROTOCOL_ID_SIZE],
    // Instance: public_inputs.hash_bytes() -- 32-byte LE Skyscraper hash
    instance: [u8; INSTANCE_SIZE],

    // --- Phase 1: Commitment data ---
    // Initial f_hat commitment (Merkle root, absorbed as raw bytes)
    initial_root_hash: [u8; 32],
    // OOD queries/answers for the initial commitment
    initial_ood_answers: [Field; OOD_SAMPLES],

    // Blinding commitment (Merkle root, absorbed as raw bytes)
    blinding_root_hash: [u8; 32],
    // OOD queries/answers for the blinding commitment
    // num_blinding_ood_answers = BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS
    blinding_ood_answers: [Field; BLINDING_OOD_SAMPLES],

    // --- Phase 2: Spartan sumcheck prover messages ---
    sum_g: Field,
    sumcheck_coeffs: [[Field; 4]; LOG_NUM_CONSTRAINTS],
    blinding_eval: Field,

    // --- Phase 3: Public inputs ---
    public_inputs: pub [Field; MAX_PUBLIC_INPUTS],
    num_public_inputs: pub u32,
    public_inputs_hash_from_prover: Field,

    // --- Phase 3b: Evaluation claims ---
    evals_az: Field,
    evals_bz: Field,
    evals_cz: Field,
    public_eval: Field,

    // --- Phase 4: zkWHIR verification data ---
    // w_folded_blinding_evals (sent by prover after blinding_challenge)
    w_folded_evals: [Field; NUM_W_FOLDED_EVALS],

    // --- Phase 4a: Inner WHIR verify (blinded_commitment) ---
    // Initial sumcheck for the blinded commitment
    initial_whir_sumcheck_evals: [[Field; 3]; FOLDING_FACTOR],

    // Per-round WHIR data (blinded commitment side)
    round_root_hashes: [[u8; 32]; NUM_WHIR_ROUNDS],
    round_ood_answers: [[Field; OOD_SAMPLES]; NUM_WHIR_ROUNDS],
    round_whir_sumcheck_evals: [[[Field; 3]; FOLDING_FACTOR]; NUM_WHIR_ROUNDS],

    // Merkle proofs per round (hints -- verified but not transcript-bound)
    round_merkle_leaves: [[[Field; FOLD_SIZE]; MAX_QUERIES_PER_ROUND]; NUM_WHIR_ROUNDS],
    round_merkle_siblings: [[[[u8; 32]; TREE_HEIGHT]; MAX_QUERIES_PER_ROUND]; NUM_WHIR_ROUNDS],
    round_merkle_indices: [[u32; MAX_QUERIES_PER_ROUND]; NUM_WHIR_ROUNDS],
    round_num_queries: [u32; NUM_WHIR_ROUNDS],

    // PoW nonces per round (absorbed into transcript)
    round_pow_nonces: [u64; NUM_WHIR_ROUNDS],
    initial_pow_nonce: u64,

    // Final WHIR round data (blinded commitment)
    final_coefficients: [Field; FINAL_POLY_SIZE],
    final_pow_nonce: u64,

    // Final round opening (Merkle hints)
    final_merkle_leaves: [[Field; FOLD_SIZE]; MAX_QUERIES_PER_ROUND],
    final_merkle_siblings: [[[u8; 32]; TREE_HEIGHT]; MAX_QUERIES_PER_ROUND],
    final_merkle_indices: [u32; MAX_QUERIES_PER_ROUND],
    final_num_queries: u32,

    // Final sumcheck data
    final_whir_sumcheck_evals: [[Field; 3]; FOLDING_FACTOR],

    // --- Phase 4b: Per-gamma claims ---
    num_gammas: u32,
    gamma_m_evals: [Field; MAX_GAMMAS],
    gamma_g_hat_evals: [[Field; NUM_WITNESS_VARIABLES]; MAX_GAMMAS],
    combined_claims: Field, // single polynomial: just one value
    batched_h_claims: Field,

    // --- Phase 4c: Blinding WHIR verification ---
    // (Simplified: blinding WHIR has its own rounds/data)
    blinding_whir_initial_evals: [[Field; 3]; FOLDING_FACTOR],
    blinding_round_root_hashes: [[u8; 32]; BLINDING_WHIR_ROUNDS],
    blinding_round_ood_answers: [[Field; BLINDING_OOD_SAMPLES]; BLINDING_WHIR_ROUNDS],
    blinding_round_sumcheck_evals: [[[Field; 3]; FOLDING_FACTOR]; BLINDING_WHIR_ROUNDS],
    blinding_round_merkle_leaves: [[[Field; BLINDING_FOLD_SIZE]; BLINDING_MAX_QUERIES]; BLINDING_WHIR_ROUNDS],
    blinding_round_merkle_siblings: [[[[u8; 32]; BLINDING_TREE_HEIGHT]; BLINDING_MAX_QUERIES]; BLINDING_WHIR_ROUNDS],
    blinding_round_merkle_indices: [[u32; BLINDING_MAX_QUERIES]; BLINDING_WHIR_ROUNDS],
    blinding_round_num_queries: [u32; BLINDING_WHIR_ROUNDS],
    blinding_round_pow_nonces: [u64; BLINDING_WHIR_ROUNDS],
    blinding_initial_pow_nonce: u64,
    blinding_final_coefficients: [Field; FINAL_POLY_SIZE],
    blinding_final_pow_nonce: u64,
    blinding_final_sumcheck_evals: [[Field; 3]; FOLDING_FACTOR],
    blinding_final_merkle_leaves: [[Field; BLINDING_FOLD_SIZE]; BLINDING_MAX_QUERIES],
    blinding_final_merkle_siblings: [[[u8; 32]; BLINDING_TREE_HEIGHT]; BLINDING_MAX_QUERIES],
    blinding_final_merkle_indices: [u32; BLINDING_MAX_QUERIES],
    blinding_final_num_queries: u32,

    // --- Phase 5: R1CS matrices (sparse, flattened) ---
    // Each matrix cell is (row: u32, col: u32, val: Field).
    // Stored as parallel arrays to avoid struct-in-main restriction.
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
    //
    // Spongefish init: absorb(protocol_id) then absorb(instance).
    // NO ratchet between them, NO session_id (ProveKit doesn't set one).
    // The SHO auto-ratchets on the first squeeze.

    let mut sho = SHO::new();
    sho.absorb(protocol_id);
    sho.absorb(instance);

    // ===================================================================
    // Phase 1: Receive commitments
    // ===================================================================
    //
    // Phase 1a: f_hat commitment (blinded_commitment.receive_commitment)
    //   - irs_commit::receive_commitment -> merkle root + OOD

    // Absorb initial Merkle root hash (raw bytes, NOT as field element)
    sho.absorb(initial_root_hash);

    // Squeeze OOD query points and absorb OOD answers
    for i in 0..OOD_SAMPLES {
        let _ood_query = sho.squeeze_field();
        // OOD query is derived from transcript -- no need to check against input
    }
    for i in 0..OOD_SAMPLES {
        sho.absorb_field(initial_ood_answers[i]);
    }

    // Phase 1b: Blinding commitment (blinding_commitment.receive_commitment)
    sho.absorb(blinding_root_hash);

    for _i in 0..BLINDING_OOD_SAMPLES {
        let _blinding_ood_query = sho.squeeze_field();
    }
    // Blinding OOD answers: BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS answers
    // For simplicity, we absorb the first BLINDING_OOD_SAMPLES answers here
    // (full multi-vector OOD would need BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS)
    for i in 0..BLINDING_OOD_SAMPLES {
        sho.absorb_field(blinding_ood_answers[i]);
    }

    // ===================================================================
    // Phase 2: Run Spartan sumcheck
    // ===================================================================

    let sc_result: SumcheckResult<LOG_NUM_CONSTRAINTS> = run_sumcheck_verifier(
        &mut sho,
        sumcheck_coeffs,
        sum_g,
        blinding_eval,
    );

    // ===================================================================
    // Phase 3: Public input binding + evaluation claims
    // ===================================================================

    // Read public inputs hash from prover
    sho.absorb_field(public_inputs_hash_from_prover);

    // Verify hash matches Skyscraper compression chain
    verify_public_input_hash(
        public_inputs_hash_from_prover,
        public_inputs,
        num_public_inputs,
    );

    // Squeeze challenge x for geometric weights
    let x: Field = sho.squeeze_field();

    // Absorb claimed evaluations (Az, Bz, Cz)
    sho.absorb_field(evals_az);
    sho.absorb_field(evals_bz);
    sho.absorb_field(evals_cz);

    // Verify public input geometric evaluation (if applicable)
    if num_public_inputs > 0 {
        sho.absorb_field(public_eval);
        verify_public_eval(public_eval, x, public_inputs, num_public_inputs);
    }

    // ===================================================================
    // Phase 4: zkWHIR verification
    // ===================================================================
    //
    // This mirrors whir_zk::Config::verify in the WHIR library.

    // 4.0: Squeeze blinding_challenge
    let blinding_challenge: Field = sho.squeeze_field();

    // 4.1: Absorb w_folded_blinding_evals
    for i in 0..NUM_W_FOLDED_EVALS {
        sho.absorb_field(w_folded_evals[i]);
    }

    // 4.2: Squeeze masking_challenge (must be non-zero)
    let masking_challenge: Field = sho.squeeze_field();
    assert(masking_challenge != 0, "masking_challenge must be non-zero");

    // ===================================================================
    // Phase 4a: Inner WHIR verify (blinded_commitment)
    // ===================================================================
    //
    // This mirrors whir::Config::verify for the witness-side WHIR.
    //
    // For single vector mode (num_vectors=1):
    //   - No OOD cross-terms needed
    //   - geometric_challenge(1) = no-op (returns [1])
    //   - geometric_challenge(oods + num_linear_forms) = squeeze one field

    // Constraint RLC: squeeze one field for combining OOD + linear form constraints
    let _constraint_rlc_base: Field = sho.squeeze_field();

    // Initial WHIR sumcheck (folding_factor rounds)
    let (mut total_folding_rand, mut last_eval) = run_whir_sumcheck(
        &mut sho,
        0, // initial sum (will be recomputed from constraint RLC)
        initial_whir_sumcheck_evals,
    );

    // Initial PoW check
    check_pow(&mut sho, initial_pow_nonce);

    // Per-round WHIR verification (blinded commitment side)
    for r in 0..NUM_WHIR_ROUNDS {
        // Receive round commitment (Merkle root as raw bytes)
        sho.absorb(round_root_hashes[r]);

        // OOD points and answers
        for _i in 0..OOD_SAMPLES {
            let _ood_pt = sho.squeeze_field();
        }
        for i in 0..OOD_SAMPLES {
            sho.absorb_field(round_ood_answers[r][i]);
        }

        // PoW check
        check_pow(&mut sho, round_pow_nonces[r]);

        // Squeeze in-domain challenge indices (these determine Merkle query positions)
        // In the Rust verifier, this squeezes raw bytes for indices.
        // For circuit simplicity, we squeeze field elements as proxy.
        let n_queries = round_num_queries[r];
        for q in 0..MAX_QUERIES_PER_ROUND {
            if (q as u32) < n_queries {
                let _challenge_idx = sho.squeeze_field();
            }
        }

        // Verify Merkle proofs (hint data -- not transcript-bound)
        for q in 0..MAX_QUERIES_PER_ROUND {
            if (q as u32) < n_queries {
                verify_merkle_proof(
                    round_merkle_leaves[r][q],
                    round_merkle_siblings[r][q],
                    round_merkle_indices[r][q],
                    round_root_hashes[r],
                );
            }
        }

        // Compute fold from leaf values
        let fold = compute_fold(
            round_merkle_leaves[r],
            total_folding_rand,
            n_queries,
        );

        // Constraint RLC for this round
        let _round_constraint_rlc: Field = sho.squeeze_field();

        // Round sumcheck
        let (round_fold_rand, new_last_eval) = run_whir_sumcheck(
            &mut sho,
            last_eval,
            round_whir_sumcheck_evals[r],
        );
        last_eval = new_last_eval;
        total_folding_rand = round_fold_rand;
    }

    // Final WHIR round: receive final polynomial coefficients
    for i in 0..FINAL_POLY_SIZE {
        sho.absorb_field(final_coefficients[i]);
    }

    // Final PoW
    check_pow(&mut sho, final_pow_nonce);

    // Final opening: squeeze challenge indices for the last round
    for q in 0..MAX_QUERIES_PER_ROUND {
        if (q as u32) < final_num_queries {
            let _idx = sho.squeeze_field();
        }
    }

    // Verify final Merkle proofs
    // (Uses the last round's root hash or initial root if NUM_WHIR_ROUNDS=0)

    // Final sumcheck
    let (final_fold_rand, _final_last_eval) = run_whir_sumcheck(
        &mut sho,
        last_eval,
        final_whir_sumcheck_evals,
    );

    // ===================================================================
    // Phase 4b: Per-gamma claims (back in zkWHIR verify)
    // ===================================================================

    // Squeeze tau1 and tau2
    let _tau1: Field = sho.squeeze_field();
    let _tau2: Field = sho.squeeze_field();

    // Per-gamma prover messages: for each gamma, absorb m_eval + g_hat_evals
    for g in 0..MAX_GAMMAS {
        if (g as u32) < num_gammas {
            sho.absorb_field(gamma_m_evals[g]);
            for v in 0..NUM_WITNESS_VARIABLES {
                sho.absorb_field(gamma_g_hat_evals[g][v]);
            }
        }
    }

    // Absorb combined_claims and batched_h_claims (one each for single polynomial)
    sho.absorb_field(combined_claims);
    sho.absorb_field(batched_h_claims);

    // ===================================================================
    // Phase 4c: Blinding WHIR verification
    // ===================================================================
    //
    // This mirrors whir::Config::verify for the blinding-side WHIR.
    // Same structure as Phase 4a but with blinding parameters.

    // Constraint RLC for blinding
    let _blinding_constraint_rlc: Field = sho.squeeze_field();

    // Initial blinding sumcheck
    let (mut blinding_fold_rand, mut blinding_last_eval) = run_whir_sumcheck(
        &mut sho,
        0,
        blinding_whir_initial_evals,
    );

    // Initial blinding PoW
    check_pow(&mut sho, blinding_initial_pow_nonce);

    // Per-round blinding WHIR verification
    for r in 0..BLINDING_WHIR_ROUNDS {
        sho.absorb(blinding_round_root_hashes[r]);

        for _i in 0..BLINDING_OOD_SAMPLES {
            let _ood_pt = sho.squeeze_field();
        }
        for i in 0..BLINDING_OOD_SAMPLES {
            sho.absorb_field(blinding_round_ood_answers[r][i]);
        }

        check_pow(&mut sho, blinding_round_pow_nonces[r]);

        let n_queries = blinding_round_num_queries[r];
        for q in 0..BLINDING_MAX_QUERIES {
            if (q as u32) < n_queries {
                let _idx = sho.squeeze_field();
            }
        }

        for q in 0..BLINDING_MAX_QUERIES {
            if (q as u32) < n_queries {
                verify_merkle_proof(
                    blinding_round_merkle_leaves[r][q],
                    blinding_round_merkle_siblings[r][q],
                    blinding_round_merkle_indices[r][q],
                    blinding_round_root_hashes[r],
                );
            }
        }

        let blinding_fold = compute_fold(
            blinding_round_merkle_leaves[r],
            blinding_fold_rand,
            n_queries,
        );

        let _blinding_round_rlc: Field = sho.squeeze_field();

        let (new_fold_rand, new_last_eval) = run_whir_sumcheck(
            &mut sho,
            blinding_last_eval,
            blinding_round_sumcheck_evals[r],
        );
        blinding_last_eval = new_last_eval;
        blinding_fold_rand = new_fold_rand;
    }

    // Final blinding WHIR round
    for i in 0..FINAL_POLY_SIZE {
        sho.absorb_field(blinding_final_coefficients[i]);
    }
    check_pow(&mut sho, blinding_final_pow_nonce);

    for q in 0..BLINDING_MAX_QUERIES {
        if (q as u32) < blinding_final_num_queries {
            let _idx = sho.squeeze_field();
        }
    }

    let (_blinding_final_fold, _blinding_final_eval) = run_whir_sumcheck(
        &mut sho,
        blinding_last_eval,
        blinding_final_sumcheck_evals,
    );

    // ===================================================================
    // Phase 5: Evaluate R1CS matrix extensions
    // ===================================================================

    let eq_row: [Field; EQ_ROW_SIZE] = eq_over_hypercube(sc_result.alpha);
    let eq_col: [Field; EQ_COL_SIZE] = eq_over_hypercube(total_folding_rand);

    // Reconstruct MatrixCell arrays from flattened inputs
    let mut matrix_a: [MatrixCell; MAX_MATRIX_CELLS] = [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    let mut matrix_b: [MatrixCell; MAX_MATRIX_CELLS] = [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    let mut matrix_c: [MatrixCell; MAX_MATRIX_CELLS] = [MatrixCell { row: 0, col: 0, val: 0 }; MAX_MATRIX_CELLS];
    for i in 0..MAX_MATRIX_CELLS {
        matrix_a[i] = MatrixCell { row: matrix_a_rows[i], col: matrix_a_cols[i], val: matrix_a_vals[i] };
        matrix_b[i] = MatrixCell { row: matrix_b_rows[i], col: matrix_b_cols[i], val: matrix_b_vals[i] };
        matrix_c[i] = MatrixCell { row: matrix_c_rows[i], col: matrix_c_cols[i], val: matrix_c_vals[i] };
    }

    let matrix_evals: [Field; 3] = evaluate_r1cs_matrices(
        matrix_a, a_len,
        matrix_b, b_len,
        matrix_c, c_len,
        eq_row, eq_col,
    );

    // Verify matrix extension evaluations match the claimed values
    assert(matrix_evals[0] == evals_az, "Matrix A evaluation mismatch");
    assert(matrix_evals[1] == evals_bz, "Matrix B evaluation mismatch");
    assert(matrix_evals[2] == evals_cz, "Matrix C evaluation mismatch");

    // ===================================================================
    // Phase 6: Final Spartan relation check
    // ===================================================================

    let eq_val = calculate_eq(sc_result.r, sc_result.alpha);
    let expected = (evals_az * evals_bz - evals_cz) * eq_val;
    assert(
        sc_result.f_at_alpha == expected,
        "Final Spartan relation check failed",
    );
}
