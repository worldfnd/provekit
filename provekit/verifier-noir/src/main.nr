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
    bit_reverse_u32, BLINDING_FINAL_POLY_ARRAY_SIZE, BLINDING_FINAL_POLY_SIZE,
    BLINDING_FINAL_SC_ARRAY_SIZE, BLINDING_FINAL_SUMCHECK_ROUNDS, BLINDING_FOLD_SIZE,
    BLINDING_INITIAL_OOD_COUNT, BLINDING_MAX_QUERIES, BLINDING_MERKLE_LEAF_SIZE,
    BLINDING_OOD_SAMPLES, BLINDING_ROUND_ARRAY_SIZE, BLINDING_STIR_BYTES_PER_INDEX,
    BLINDING_TREE_HEIGHT, BLINDING_WHIR_CONSTRAINT_COUNT, BLINDING_WHIR_ROUNDS, FINAL_POLY_SIZE,
    FINAL_SC_ARRAY_SIZE, FINAL_SUMCHECK_ROUNDS, FOLD_SIZE, FOLDING_FACTOR, INITIAL_OOD_COUNT,
    INNER_WHIR_CONSTRAINT_COUNT, INTERLEAVING_DEPTH, IRS_CODEWORD_LENGTH, LOG_NUM_CONSTRAINTS,
    LOG_NUM_VARIABLES, MatrixCell, MAX_GAMMAS, MAX_MATRIX_CELLS, MAX_PUBLIC_INPUTS,
    MAX_QUERIES_PER_ROUND, NUM_BLINDING_VECTORS, NUM_W_FOLDED_EVALS, NUM_WHIR_ROUNDS,
    NUM_WITNESS_VARIABLES, OMEGA_FULL, OOD_SAMPLES, pow_u32, ROUND_ARRAY_SIZE,
    STIR_BYTES_PER_INDEX, TREE_HEIGHT, ZETA_POWERS,
};
use whir::{
    check_pow, compute_fold, generate_combination_randomness, run_whir_sumcheck,
    squeeze_stir_challenge_indices, squeeze_stir_challenges,
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
    // spongefish DomainSeparator absorbs session_id between protocol_id and
    // instance (see spongefish/src/domain_separator.rs to_verifier). In the
    // provekit flow session_id is always [0; 32].
    let session_id: [u8; 32] = [0; 32];
    sho.absorb_bytes(session_id);
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

    // Capture initial OOD points: Rust uses them as constraint points for
    // the initial-form RLC fed into the first WHIR sumcheck.
    // TODO: feed (initial_ood_queries, initial_ood_answers)
    // pairs into the `the_sum` construction for the initial inner-WHIR
    // sumcheck, weighted by oods_rlc_coeffs = constraint_rlc[NUM_LINEAR_FORMS..].
    let mut initial_ood_queries: [Field; OOD_SAMPLES] = [0; OOD_SAMPLES];
    for i in 0..OOD_SAMPLES {
        initial_ood_queries[i] = sho.squeeze_field_aligned();
    }
    for i in 0..INITIAL_OOD_COUNT {
        sho.absorb_field_aligned(initial_ood_answers[i]);
    }

    // Phase 1b: Blinding commitment (num_vectors = NUM_BLINDING_VECTORS, so
    // there are BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS OOD answers).
    sho.absorb_field_aligned(blinding_root_hash);

    // TODO: feed (blinding_initial_ood_queries,
    // blinding_ood_answers) into the blinding WHIR initial constraint RLC.
    let mut blinding_initial_ood_queries: [Field; BLINDING_OOD_SAMPLES] = [0; BLINDING_OOD_SAMPLES];
    for i in 0..BLINDING_OOD_SAMPLES {
        blinding_initial_ood_queries[i] = sho.squeeze_field_aligned();
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

    // 4.1: blinding_challenge (verifier_message) -- used below in the
    // h_value ladder for the batched_h_claims equality check.
    let beta: Field = sho.squeeze_field();

    // 4.2: w_folded_blinding_evals (prover_messages_vec)
    // TODO: port extract_m_evals (first element of each
    // (NUM_WITNESS_VARIABLES+1)-sized block) and feed the resulting m_evals
    // into the witness-side WHIR evaluations via modified_evaluations =
    // evaluations + m_evals (whir_zk/verifier.rs L110-114).
    for i in 0..NUM_W_FOLDED_EVALS {
        sho.absorb_field(w_folded_evals[i]);
    }

    // 4.3: masking_challenge (verifier_message)
    let masking_challenge: Field = sho.squeeze_field();
    assert(masking_challenge != 0, "masking_challenge must be non-zero");

    // 4.4: STIR opening of initial blinded commitment (irs_commit::verify)
    // Squeeze and decode the in-domain query indices BIG-ENDIAN from
    // STIR_BYTES_PER_INDEX-byte chunks, reduced mod IRS_CODEWORD_LENGTH. These
    // indices feed the coset expansion that builds h_gammas below (see
    // all_gammas in whir_zk/mod.rs). Byte count matches what
    // squeeze_stir_challenges would advance.
    let initial_query_indices: [u32; MAX_QUERIES_PER_ROUND] = squeeze_stir_challenge_indices::<
        MAX_QUERIES_PER_ROUND,
        STIR_BYTES_PER_INDEX,
    >(&mut sho, IRS_CODEWORD_LENGTH);

    // 4.5: tau1 (verifier_message) -- used in build_combined_and_subproof_claims
    let tau1: Field = sho.squeeze_field();

    // 4.6: tau2 (verifier_message) -- used to RLC m_evals/g_hat_evals/h across gammas
    let tau2: Field = sho.squeeze_field();

    // --- Expand in-domain query indices into coset gamma points ---
    //
    // Mirrors whir_zk::Config::all_gammas (whir_zk/mod.rs L213-229) composed
    // with ProveKit's RSFr::evaluation_points (provekit/common/src/ntt.rs
    // L22-42), which bit-reverses each raw index before mapping it to the
    // IRS sub-domain:
    //   alpha = RSFr::generator(IRS_CODEWORD_LENGTH)^bit_reverse(idx, TREE_HEIGHT)
    //
    // Since the `omega_powers` lookup in all_gammas returns that same
    // bit-reversed index, the coset_offset raised from omega_full is:
    //   coset_offset = OMEGA_FULL^bit_reverse(idx, TREE_HEIGHT)
    // and each of INTERLEAVING_DEPTH gammas is coset_offset * ZETA_POWERS[j].
    let mut h_gammas: [Field; MAX_GAMMAS] = [0; MAX_GAMMAS];
    for q in 0..MAX_QUERIES_PER_ROUND {
        let rev_idx = bit_reverse_u32(initial_query_indices[q], TREE_HEIGHT);
        let coset_offset: Field = pow_u32(OMEGA_FULL, rev_idx);
        for j in 0..INTERLEAVING_DEPTH {
            h_gammas[q * INTERLEAVING_DEPTH + j] = coset_offset * ZETA_POWERS[j];
        }
    }

    // 4.7: Per-gamma prover messages
    // For each gamma point, absorb m_eval + 13 g_hat_evals = 14 fields.
    // MAX_GAMMAS = num_gammas = 1016 by protocol (see generate_noir_inputs.rs:750).
    // Batched into 3-gamma aligned groups (42 absorbs = 14 rate cycles) to
    // eliminate runtime lane dispatch. 1016 = 3 * 338 + 2, so 338 full
    // batches + 1 trailing 2-gamma batch.
    assert(
        num_gammas == MAX_GAMMAS,
        "num_gammas must equal MAX_GAMMAS for batched absorb",
    );
    for batch in 0..338 {
        sho.absorb_3_gammas(gamma_m_evals, gamma_g_hat_evals, batch * 3);
    }
    sho.absorb_2_gammas(gamma_m_evals, gamma_g_hat_evals, 338 * 3);

    // 4.8: combined_claims (prover_messages_vec, 1 per polynomial)
    sho.absorb_field(combined_claims);

    // 4.9: batched_h_claims (prover_messages_vec, 1 per polynomial)
    sho.absorb_field(batched_h_claims);

    // --- Build m_claim, g_hat_claims, and expected_batched_h_claim ---
    //
    // Mirrors whir_zk/verifier.rs L85-107 (num_polynomials = 1 in our config):
    //   m_claim                   = sum_k tau2^k * gamma_m_evals[k]
    //   g_hat_claims[j]           = sum_k tau2^k * gamma_g_hat_evals[k][j]
    //   expected_batched_h_claim  = sum_k tau2^k * h(h_gammas[k], beta)
    // where
    //   h(gamma, beta) = m_eval + sum_j beta^(j+1) * gamma^(2^j) * g_hat_j
    // with beta on a linear ladder (beta, beta^2, beta^3, ...) and gamma on a
    // squaring ladder (gamma, gamma^2, gamma^4, ...) in lock-step over j.
    let mut m_claim: Field = 0;
    let mut g_hat_claims: [Field; NUM_WITNESS_VARIABLES] = [0; NUM_WITNESS_VARIABLES];
    let mut expected_batched_h_claim: Field = 0;
    let mut tau2_power: Field = 1;
    for k in 0..MAX_GAMMAS {
        let m_eval_k = gamma_m_evals[k];
        m_claim += tau2_power * m_eval_k;

        let mut h_value: Field = m_eval_k;
        let mut beta_power: Field = beta;
        let mut gamma_power: Field = h_gammas[k];
        for j in 0..NUM_WITNESS_VARIABLES {
            let g_hat_eval = gamma_g_hat_evals[k][j];
            g_hat_claims[j] += tau2_power * g_hat_eval;
            h_value += beta_power * gamma_power * g_hat_eval;
            beta_power *= beta;
            gamma_power = gamma_power * gamma_power;
        }
        expected_batched_h_claim += tau2_power * h_value;
        tau2_power *= tau2;
    }
    assert(
        batched_h_claims == expected_batched_h_claim,
        "batched_h_claims mismatch (whir_zk/verifier.rs L120)",
    );

    // --- Recompute expected_combined_claims from (m_claim, g_hat_claims, tau1) ---
    //
    // Mirrors combine_claim_from_components in whir_zk/utils.rs L157-165:
    //   combined = m_claim + 2 * tau1 * univariate_eval(g_hat_claims, tau1)
    //   univariate_eval([c_0, ..., c_{mu-1}], tau1) = sum_j c_j * tau1^j
    //
    // The factor 2 compensates for the (ell+1)-variable embedding where g_hat
    // coefficients occupy only even slots (Rust comment at L158-163).
    let mut univar_g_hat: Field = 0;
    let mut tau1_power: Field = 1;
    for j in 0..NUM_WITNESS_VARIABLES {
        univar_g_hat += tau1_power * g_hat_claims[j];
        tau1_power *= tau1;
    }
    let expected_combined_claims: Field = m_claim + 2 * tau1 * univar_g_hat;
    assert(
        combined_claims == expected_combined_claims,
        "combined_claims mismatch (whir_zk/verifier.rs L124)",
    );

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
    // count = OOD_SAMPLES + NUM_LINEAR_FORMS (e.g. 1 + 4 = 5)
    // TODO: use `constraint_rlc` to build the initial
    // sumcheck sum `the_sum = sum_i initial_form_rlc[i] * evals[i] + sum_i
    // oods_rlc[i] * oods_matrix[i]` (whir/verifier.rs L106-114) and pass
    // `the_sum` instead of 0 into the initial run_whir_sumcheck call below.
    // initial_form_rlc = constraint_rlc[0..NUM_LINEAR_FORMS],
    // oods_rlc = constraint_rlc[NUM_LINEAR_FORMS..].
    let constraint_rlc: [Field; INNER_WHIR_CONSTRAINT_COUNT] =
        generate_combination_randomness(&mut sho, INNER_WHIR_CONSTRAINT_COUNT);

    // Accumulator for all folding randomness across sumcheck phases (total = m)
    let mut total_folding_rand: [Field; LOG_NUM_VARIABLES] = [0; LOG_NUM_VARIABLES];

    // 4a.3: Initial WHIR sumcheck (FOLDING_FACTOR rounds, quadratic)
    // TODO: replace the `0` initial sum with `the_sum`
    // from whir/verifier.rs L106-114:
    //   the_sum = sum_i initial_form_rlc[i] * (evals[i] + m_evals[i])
    //           + sum_j oods_rlc[j] * initial_ood_answers[j]
    // where initial_form_rlc = constraint_rlc[0..NUM_LINEAR_FORMS] and
    // oods_rlc = constraint_rlc[NUM_LINEAR_FORMS..]. The `m_evals[i]`
    let (initial_fold_rand, mut last_eval) =
        run_whir_sumcheck(&mut sho, 0, initial_whir_sumcheck_coeffs);

    // Store initial folding randomness
    for i in 0..FOLDING_FACTOR {
        total_folding_rand[i] = initial_fold_rand[i];
    }

    // 4a.4: Per-round WHIR verification (for NUM_WHIR_ROUNDS > 0)
    // Capture per-round OOD points for use in the per-round constraint RLC.
    let mut round_ood_pts: [[Field; OOD_SAMPLES]; ROUND_ARRAY_SIZE] =
        [[0; OOD_SAMPLES]; ROUND_ARRAY_SIZE];
    for r in 0..NUM_WHIR_ROUNDS {
        // Receive round commitment (irs_commit::receive_commitment)
        sho.absorb_field(round_root_hashes[r]);

        for i in 0..OOD_SAMPLES {
            round_ood_pts[r][i] = sho.squeeze_field();
        }
        for i in 0..OOD_SAMPLES {
            sho.absorb_field(round_ood_answers[r][i]);
        }

        // Between-round PoW (whir/verifier.rs: round_config.pow.verify)
        check_pow(&mut sho, round_pow_nonces[r]);

        // Open previous commitment: STIR challenge indices (squeeze bytes)
        squeeze_stir_challenges(&mut sho, round_num_queries[r], STIR_BYTES_PER_INDEX);

        // Merkle proofs open the PREVIOUS commitment (initial for r=0,
        // round_configs[r-1] for r>0). Matches Rust-side at
        // generate_noir_inputs.rs:605-609.
        let verify_root: Field =
            if r == 0 { initial_root_hash } else { round_root_hashes[r - 1] };

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
                    verify_root,
                );
            }
        }

        // Compute fold from leaf values
        // TODO: assert that this `fold` is consistent with
        // the per-round sumcheck claim at `last_eval`, i.e. enforce
        //   sum_q per_query_weight(q) * fold[q] == (contribution to last_eval)
        // per whir/verifier.rs L218-226 (in-domain constraint direct check).
        // Without this, a prover can commit to arbitrary leaves and pass.
        let fold = compute_fold(round_merkle_leaves[r], initial_fold_rand, n_queries);

        // Constraint RLC for this round (geometric_challenge)
        // TODO: use `round_constraint_rlc` powers to batch
        // (this round's OOD answers + in-domain constraints) into
        // `last_eval` before calling run_whir_sumcheck below -- see
        // whir/verifier.rs L178-180: the_sum += dot(constraint_rlc_coeffs, constraint_values).
        let round_constraint_rlc: Field = sho.squeeze_field();

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
    //
    // TODO: `final_last_eval` is the inner-WHIR
    // sumcheck's exit value. It feeds the FinalClaim linear_form_rlc check:
    //   linear_form_rlc = final_last_eval / poly_eval
    //                   - sum_{round, k} round_rlc[k] * round_weight_k.mle_evaluate(eval_point[start..])
    //   assert sum_i initial_form_rlc[i] * weight_i.mle_evaluate(eval_point) == linear_form_rlc
    // Weights: PrefixCovector per matrix (= matrix_evals below), blinding
    // OffsetCovector, public_weight if MAX_PUBLIC_INPUTS > 0. Also need the
    // final_vector-based `weights.evaluate(Identity, &final_vector) == evals`
    // direct check per whir/verifier.rs L218-226.
    let (final_fold_rand, final_last_eval) =
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
    // TODO: use `blinding_constraint_rlc` to build
    // "the_sum" for the blinding initial sumcheck, same structure as
    // gap #8 but applied to blinding commitments / blinding OOD answers.
    let blinding_constraint_rlc: [Field; BLINDING_WHIR_CONSTRAINT_COUNT] =
        generate_combination_randomness(&mut sho, BLINDING_WHIR_CONSTRAINT_COUNT);

    // Blinding initial sumcheck
    // TODO: replace `0` with blinding `the_sum` from
    // blinding_constraint_rlc + blinding evaluation claims.
    let (blinding_initial_fold_rand, mut blinding_last_eval) =
        run_whir_sumcheck(&mut sho, 0, blinding_whir_initial_coeffs);

    // Per-round blinding WHIR verification
    let mut blinding_round_ood_pts: [[Field; BLINDING_OOD_SAMPLES]; BLINDING_ROUND_ARRAY_SIZE] =
        [[0; BLINDING_OOD_SAMPLES]; BLINDING_ROUND_ARRAY_SIZE];
    for r in 0..BLINDING_WHIR_ROUNDS {
        sho.absorb_field(blinding_round_root_hashes[r]);

        for i in 0..BLINDING_OOD_SAMPLES {
            blinding_round_ood_pts[r][i] = sho.squeeze_field();
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

        // Opens the PREVIOUS blinding commitment (see inner WHIR above).
        let blinding_verify_root: Field =
            if r == 0 { blinding_root_hash } else { blinding_round_root_hashes[r - 1] };

        // Blinding round 0's leaf is NUM_BLINDING_VECTORS * BLINDING_FOLD_SIZE
        // fields wide (one row of the initial interleaved commitment).
        // Rounds 1+ open a folded tree whose rows are BLINDING_FOLD_SIZE
        // fields wide; Prover.toml pads them into the same typed array.
        // Slice the first BLINDING_FOLD_SIZE fields for the narrower hash.
        let n_queries = blinding_round_num_queries[r];
        for q in 0..BLINDING_MAX_QUERIES {
            if (q as u32) < n_queries {
                if r == 0 {
                    verify_merkle_proof_dynamic(
                        blinding_round_merkle_leaves[r][q],
                        blinding_round_merkle_leaf_sizes[r],
                        blinding_round_merkle_siblings[r][q],
                        blinding_round_merkle_tree_heights[r],
                        blinding_round_merkle_indices[r][q],
                        blinding_verify_root,
                    );
                } else {
                    let mut small_leaf: [Field; BLINDING_FOLD_SIZE] =
                        [0; BLINDING_FOLD_SIZE];
                    for i in 0..BLINDING_FOLD_SIZE {
                        small_leaf[i] = blinding_round_merkle_leaves[r][q][i];
                    }
                    verify_merkle_proof_dynamic(
                        small_leaf,
                        BLINDING_FOLD_SIZE,
                        blinding_round_merkle_siblings[r][q],
                        blinding_round_merkle_tree_heights[r],
                        blinding_round_merkle_indices[r][q],
                        blinding_verify_root,
                    );
                }
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
        // TODO: assert `blinding_fold` is consistent with
        // the blinding per-round sumcheck claim (mirror of gap #12 on
        // blinding side). Merkle alone is not sufficient.
        let blinding_fold =
            compute_fold(blinding_fold_leaves, blinding_initial_fold_rand, n_queries);

        // TODO: use `blinding_round_rlc` powers to fold this
        // round's OOD answers + in-domain constraints into blinding_last_eval
        // before the sumcheck below. Also track `new_fold_rand` for
        // multi-round FinalClaim (currently dropped).
        let blinding_round_rlc: Field = sho.squeeze_field();

        let (new_fold_rand, new_last_eval) = run_whir_sumcheck(
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
    // Blinding final opens a folded tree (BLINDING_FOLD_SIZE-wide rows);
    // Prover.toml pads them into the 112-wide typed array. Slice to match.
    for q in 0..BLINDING_MAX_QUERIES {
        if (q as u32) < blinding_final_num_queries {
            let mut small_leaf: [Field; BLINDING_FOLD_SIZE] = [0; BLINDING_FOLD_SIZE];
            for i in 0..BLINDING_FOLD_SIZE {
                small_leaf[i] = blinding_final_merkle_leaves[q][i];
            }
            verify_merkle_proof_dynamic(
                small_leaf,
                BLINDING_FOLD_SIZE,
                blinding_final_merkle_siblings[q],
                blinding_final_merkle_tree_height,
                blinding_final_merkle_indices[q],
                blinding_final_root,
            );
        }
    }

    // Blinding final sumcheck: BLINDING_FINAL_SUMCHECK_ROUNDS=0 means no rounds.
    // The array is sized BLINDING_FINAL_SC_ARRAY_SIZE=1 for Noir, but we skip execution.
    // TODO: when this branch is live, assert
    //   blinding_final_eval == sum_k tau2^k * beq((gamma_k, -rho), final_eval_point)
    // via `construct_batched_eq_weights_from_gammas` (whir_zk/utils.rs L279-348)
    // MLE-evaluated at the final blinding folding point. Requires h_gammas
    // and a port of fill_eq_weights_at_gamma's squaring ladder.
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
    // matrix_evals[k] = M_k_MLE(alpha, total_folding_rand). These are the
    // values of the PrefixCovector weights at the final WHIR folding point;
    // they feed the FinalClaim::verify RLC below. They are intentionally
    // not compared to evals_az/bz/cz here: those scalars are (M_k * z)(alpha),
    // which is a different object.
    //
    // TODO: port FinalClaim::verify (whir/mod.rs) and enforce
    //   linear_form_rlc = final_last_eval / poly_eval
    //                   - sum_{round, k} round_weight_rlc[k] * round_weight_k.mle_evaluate(...)
    //   assert sum_i initial_form_rlc[i] * weight_i.mle_evaluate(final_fold_point) == linear_form_rlc
    // where weight_i for i in 0..3 is PrefixCovector(M_i^T * eq_alpha) -- whose MLE
    // at total_folding_rand equals matrix_evals[i] -- and weight_3 is the
    // blinding OffsetCovector (m_eval correction from w_folded_evals applies
    // on the claimed side). `poly_eval` is
    // MultilinearExtension(final_fold_rand).evaluate(&final_coefficients).
    //
    // TODO: when num_polynomials > 1 or num_vectors > 1,
    // combined_claims / batched_h_claims become length-n vectors and all
    // downstream checks must loop. Currently hard-coded to 1.

    // ===================================================================
    // Phase 6: Final Spartan relation check
    // ===================================================================

    let eq_val = calculate_eq(sc_result.r, sc_result.alpha);
    let expected = (evals_az * evals_bz - evals_cz) * eq_val;
    assert(sc_result.f_at_alpha == expected, "Final Spartan relation check failed");
}
