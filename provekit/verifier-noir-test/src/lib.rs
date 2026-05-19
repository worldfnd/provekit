//! Test-only library exposing fixed Poseidon2 KAT inputs / outputs so the
//! Cargo and Nargo sides can reference the same constants.

use {
    ark_bn254::Fr, ark_ff::PrimeField, provekit_common::poseidon2::Poseidon2Sponge,
    spongefish::DuplexSpongeInterface,
};

/// KAT input for cross-implementation Poseidon2 permutation testing.
pub fn kat_input() -> [Fr; 4] {
    [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ]
}

/// Compute the expected output by running the Rust `poseidon2` crate.
pub fn kat_expected() -> [Fr; 4] {
    poseidon2::permutation::poseidon2_permutation(&kat_input())
}

/// Render a field element as a Noir-compatible decimal literal.
pub fn fr_to_noir_literal(fe: Fr) -> String {
    fe.into_bigint().to_string()
}

/// Run the canonical sponge KAT sequence through spongefish's
/// `Poseidon2Sponge` and return the four squeezed field elements.
///
/// Sequence: `default() -> absorb(field_to_bytes(1)) ->
/// absorb(field_to_bytes(2)) -> 4 x squeeze(32 bytes)`. Each 32-byte squeeze is
/// interpreted as one field element via `Fr::from_le_bytes_mod_order`.
pub fn sponge_kat_expected() -> [Fr; 4] {
    let mut s = Poseidon2Sponge::default();
    let one = fr_to_le_bytes(Fr::from(1u64));
    let two = fr_to_le_bytes(Fr::from(2u64));
    s.absorb(&one);
    s.absorb(&two);

    let mut outputs = [Fr::from(0u64); 4];
    for output in outputs.iter_mut() {
        let mut buf = [0u8; 32];
        s.squeeze(&mut buf);
        *output = Fr::from_le_bytes_mod_order(&buf);
    }
    outputs
}

fn fr_to_le_bytes(fe: Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bi = fe.into_bigint();
    for (i, limb) in bi.0.iter().enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    buf
}

/// Lane-grain duplex sponge replayed in Rust using the raw Poseidon2
/// permutation (no spongefish state-machine plumbing — we re-implement the
/// same state machine here so the test can set arbitrary initial state).
///
/// This must produce exactly the same outputs as Noir's `Transcript`. If they
/// disagree, either:
///   - the Rust replay below has a bug, OR
///   - the Noir `sponge.nr` state machine drifted from spongefish semantics.
#[allow(unused_assignments)]
pub fn lane_sponge_replay(
    mut state: [Fr; 4],
    mut absorb_pos: u32,
    mut squeeze_pos: u32,
    absorbs: &[Fr],
    squeeze_count: usize,
) -> Vec<Fr> {
    const RATE: u32 = 3;

    for &fe in absorbs {
        squeeze_pos = RATE;
        if absorb_pos == RATE {
            state = poseidon2::permutation::poseidon2_permutation(&state);
            absorb_pos = 0;
        }
        state[absorb_pos as usize] = fe;
        absorb_pos += 1;
    }

    let mut out = Vec::with_capacity(squeeze_count);
    for _ in 0..squeeze_count {
        // Mirrors spongefish's `squeeze` reset (duplex_sponge.rs line 222)
        // and Noir's `sponge.nr::squeeze_field` line 61. The assignment is
        // a no-op for this function's current call patterns (we return
        // after the squeeze loop) but is required to keep the state machine
        // faithful — Phase 2 may add interleaved absorb/squeeze sequences.
        absorb_pos = 0;
        if squeeze_pos == RATE {
            squeeze_pos = 0;
            state = poseidon2::permutation::poseidon2_permutation(&state);
        }
        out.push(state[squeeze_pos as usize]);
        squeeze_pos += 1;
    }

    out
}

/// Run the canonical merkle KAT (`length_iv_hash([1, 2])` in Noir terms)
/// through the Rust `poseidon2::poseidon2_hash` reference.
pub fn merkle_kat_expected() -> Fr {
    poseidon2::poseidon2_hash(&[Fr::from(1u64), Fr::from(2u64)])
}

/// Build a valid 2-round Spartan sumcheck transcript with `sum_g = 12`,
/// `blinding_eval = 7`, using the convention `h_i = [saved/2, 0, 0, 0]`
/// (constant polynomial whose two boolean-hypercube evaluations both equal
/// half the running saved value, so `h_i(0) + h_i(1) == saved` always).
///
/// Returns the two `h_polys` rows (each `[c0, c1, c2, c3]`) AND the
/// `f_at_alpha` the verifier should compute. Both Noir and the Rust replay
/// consume the same `(sum_g, h_polys, blinding_eval)`; they must agree on
/// `f_at_alpha`.
pub fn sumcheck_kat_construct() -> ([[Fr; 4]; 2], Fr) {
    use ark_ff::Field as _; // for .inverse()

    let sum_g = Fr::from(12u64);
    let blinding_eval = Fr::from(7u64);

    // Simulate Transcript::new() => fresh lane sponge.
    let mut state = [Fr::from(0u64); 4];
    let mut absorb_pos: u32 = 0;
    let mut squeeze_pos: u32 = SUMCHECK_KAT_RATE;

    const M0: usize = 2;

    // Phase 1: squeeze M0 challenges (`r`).
    let mut _r = [Fr::from(0u64); M0];
    for slot in _r.iter_mut() {
        *slot = sumcheck_squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
    }

    // Phase 2: absorb sum_g.
    sumcheck_absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, sum_g);

    // Phase 3: squeeze rho, init saved = rho * sum_g.
    let rho = sumcheck_squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
    let mut saved = rho * sum_g;

    // Phase 4: per-round h_polys + assertions.
    let mut h_polys = [[Fr::from(0u64); 4]; M0];
    let two_inv = Fr::from(2u64)
        .inverse()
        .expect("2 is invertible in BN254 scalar field");
    for row in h_polys.iter_mut() {
        // Pick h_i = [saved/2, 0, 0, 0] => constant polynomial,
        // h_i(0) + h_i(1) = saved/2 + saved/2 = saved. Soundness check passes.
        let c0 = saved * two_inv;
        *row = [c0, Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)];

        // Absorb the 4 coefficients.
        for &coeff in row.iter() {
            sumcheck_absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, coeff);
        }

        // Squeeze alpha_i (consumed only to advance the transcript), update
        // saved = h_i(alpha_i) = c0 (constant poly, c1..c3 are zero).
        let _alpha_i = sumcheck_squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
        saved = c0;
    }

    // Phase 5: absorb blinding_eval.
    sumcheck_absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, blinding_eval);

    // f_at_alpha = saved - rho * blinding_eval.
    let f_at_alpha = saved - rho * blinding_eval;

    (h_polys, f_at_alpha)
}

const SUMCHECK_KAT_RATE: u32 = 3;

fn sumcheck_absorb_one(state: &mut [Fr; 4], absorb_pos: &mut u32, squeeze_pos: &mut u32, fe: Fr) {
    *squeeze_pos = SUMCHECK_KAT_RATE;
    if *absorb_pos == SUMCHECK_KAT_RATE {
        *state = poseidon2::permutation::poseidon2_permutation(state);
        *absorb_pos = 0;
    }
    state[*absorb_pos as usize] = fe;
    *absorb_pos += 1;
}

fn sumcheck_squeeze_one(state: &mut [Fr; 4], absorb_pos: &mut u32, squeeze_pos: &mut u32) -> Fr {
    *absorb_pos = 0;
    if *squeeze_pos == SUMCHECK_KAT_RATE {
        *squeeze_pos = 0;
        *state = poseidon2::permutation::poseidon2_permutation(state);
    }
    let out = state[*squeeze_pos as usize];
    *squeeze_pos += 1;
    out
}

/// Canonical Phase 1B transcript KAT sequence (same as Noir's
/// `transcript_init_absorb_squeeze_matches_frozen_kat`):
///
///   state = [10, 20, 30, 40], absorb_pos = 1, squeeze_pos = 3
///   absorb 7, absorb 8
///   squeeze, squeeze -> [a, b]
pub fn transcript_kat_expected() -> [Fr; 2] {
    let state = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
    ];
    let absorbs = [Fr::from(7u64), Fr::from(8u64)];
    let out = lane_sponge_replay(state, 1, 3, &absorbs, 2);
    [out[0], out[1]]
}

/// Compute `M^T . eq(alpha, .)` for the 3x4 test matrix A from
/// `provekit/common/src/utils/sumcheck.rs::make_test_r1cs`:
///
///   A = [[1, 2, 0, 0],
///        [0, 0, 3, 0],
///        [1, 0, 0, 1]]
///
/// with alpha = [2, 3], truncated to 3 constraints. Matches the
/// `test_multiply_transposed_by_eq_alpha` expected_a vector exactly.
pub fn matrix_eval_kat_expected() -> [Fr; 4] {
    // alpha = [2, 3]; eq big-endian hypercube on 2 bits:
    //   index 0 = eq([2,3], [0,0]) = (1-2)(1-3) =  2
    //   index 1 = eq([2,3], [0,1]) = (1-2)(3)   = -3
    //   index 2 = eq([2,3], [1,0]) = (2)(1-3)   = -4
    //   index 3 = eq([2,3], [1,1]) = (2)(3)     =  6
    // Truncate to 3 (drop index 3).
    let one = Fr::from(1u64);
    let a0 = Fr::from(2u64);
    let a1 = Fr::from(3u64);
    let eq0 = (one - a0) * (one - a1); //  2
    let eq1 = (one - a0) * a1; // -3
    let eq2 = a0 * (one - a1); // -4
                               // Matrix A rows:
                               //   row 0: (col 0, val 1), (col 1, val 2)
                               //   row 1: (col 2, val 3)
                               //   row 2: (col 0, val 1), (col 3, val 1)
    [
        Fr::from(1u64) * eq0 + Fr::from(1u64) * eq2, // col 0: -2
        Fr::from(2u64) * eq0,                        // col 1:  4
        Fr::from(3u64) * eq1,                        // col 2: -9
        Fr::from(1u64) * eq2,                        // col 3: -4
    ]
}

/// Build a 4-leaf Merkle tree using `poseidon2_hash` and return
/// `(siblings_along_path_to_index_1, root)`.
///
/// Layout:
///   leaves = [[1], [2], [3], [4]]
///   leaf_hash_i = poseidon2_hash([leaf_i])
///   h01 = poseidon2_hash([leaf_hash_0, leaf_hash_1])
///   h23 = poseidon2_hash([leaf_hash_2, leaf_hash_3])
///   root = poseidon2_hash([h01, h23])
///
/// Path to leaf index 1 (binary 01 -> LSB=1 means we're right child at leaf
/// level):   siblings[0] = leaf_hash_0 (the LEFT sibling at leaf level)
///   siblings[1] = h23         (the right sibling at level 1)
pub fn merkle_path_kat_expected() -> ([Fr; 2], Fr) {
    let leaf0 = poseidon2::poseidon2_hash(&[Fr::from(1u64)]);
    let leaf1 = poseidon2::poseidon2_hash(&[Fr::from(2u64)]);
    let leaf2 = poseidon2::poseidon2_hash(&[Fr::from(3u64)]);
    let leaf3 = poseidon2::poseidon2_hash(&[Fr::from(4u64)]);

    let h01 = poseidon2::poseidon2_hash(&[leaf0, leaf1]);
    let h23 = poseidon2::poseidon2_hash(&[leaf2, leaf3]);
    let root = poseidon2::poseidon2_hash(&[h01, h23]);

    let siblings = [leaf0, h23];
    (siblings, root)
}

/// Compute `HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13])`, which is
/// `poseidon2_hash([DST_FE, 7, 11, 13])` per the Rust reference at
/// `provekit/common/src/hash_config.rs::hash_poseidon2`.
pub fn public_input_kat_expected() -> Fr {
    provekit_common::HashConfig::Poseidon2.hash_field_elements(&[
        Fr::from(7u64),
        Fr::from(11u64),
        Fr::from(13u64),
    ])
}

/// The Poseidon2 DST constant the Rust prover/verifier uses:
/// `SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p`. Computed here so the
/// Noir verifier can pin this constant in source.
pub fn public_inputs_dst_fe() -> Fr {
    use sha2::{Digest, Sha256};
    Fr::from_le_bytes_mod_order(&Sha256::digest(b"PROVEKIT_PUBLIC_INPUTS_V1"))
}

/// Compute the first 4 powers of the squeezed challenge from the canonical
/// transcript state used by Phase 3B-i KAT.
///
/// Sequence: init_from_pre_absorbed_state(state=[10,20,30,40], absorb_pos=1,
/// squeeze_pos=3); squeeze x; return [1, x, x^2, x^3].
pub fn geometric_challenge_kat_expected() -> [Fr; 4] {
    let state = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
    ];
    // Use lane_sponge_replay (already defined for transcript_kat). Squeeze 1 field
    // as `x`.
    let xs = lane_sponge_replay(state, 1, 3, &[], 1);
    let x = xs[0];

    let mut result = [Fr::from(0u64); 4];
    result[0] = Fr::from(1u64);
    result[1] = x;
    result[2] = x * x;
    result[3] = x * x * x;
    result
}

/// Byte-grain duplex sponge replay used to capture the expected output of
/// `Transcript::squeeze_bytes_n::<N>()` for the canonical Phase 3B-iii state.
///
/// Spongefish's underlying state is `[u8; 128]` with `squeeze_pos` measured in
/// bytes 0..96 (RATE = 96 bytes = 3 lanes of 32). When squeezing N bytes:
///   - if `squeeze_pos == 96`, run the permutation (lane-grain) and reset
///     `squeeze_pos` to 0.
///   - read one byte from `state_bytes[squeeze_pos]` and advance.
///
/// Since the lane-grain `Sponge` in `provekit/verifier-noir` carries the same
/// state in `[Fr; 4]` form, we lift to bytes by encoding each Fr with LE
/// (matching Noir's `Field::to_le_bytes::<32>()` and spongefish's
/// `field_to_bytes_le`).
///
/// The canonical KAT state for byte squeeze is the same as the field-grain
/// transcript KAT: lanes = [10, 20, 30, 40], absorb_pos = 1 (lane units),
/// squeeze_pos = 3 (lane units). Translated to bytes: byte_absorb_pos =
/// 1 * 32 = 32, byte_squeeze_pos = 3 * 32 = 96.
///
/// The byte stream this function returns is bit-exact to what spongefish's
/// `Poseidon2Sponge` would produce starting from the byte-equivalent state.
pub fn byte_sponge_replay(
    mut state: [Fr; 4],
    _absorb_pos_lane: u32,
    mut squeeze_pos_byte: u32,
    squeeze_byte_count: usize,
) -> Vec<u8> {
    const RATE_BYTES: u32 = 96;

    // Reset absorb_pos like spongefish does on first squeeze (we do not absorb
    // here, but mirror the state-machine field for clarity).
    let mut _absorb_pos_byte = 0u32;

    let mut out = Vec::with_capacity(squeeze_byte_count);
    for _ in 0..squeeze_byte_count {
        if squeeze_pos_byte == RATE_BYTES {
            squeeze_pos_byte = 0;
            state = poseidon2::permutation::poseidon2_permutation(&state);
        }
        let lane_idx = (squeeze_pos_byte / 32) as usize;
        let byte_in_lane = (squeeze_pos_byte % 32) as usize;
        let lane_bytes = fr_to_le_bytes(state[lane_idx]);
        out.push(lane_bytes[byte_in_lane]);
        squeeze_pos_byte += 1;
        _absorb_pos_byte = 0;
    }
    out
}

/// Canonical Phase 3B-iii byte-squeeze KAT sequence (matches the Noir
/// `squeeze_bytes_matches_frozen_kat` test):
///
///   init_from_pre_absorbed_state(state = [10, 20, 30, 40], absorb_pos = 1,
///                                squeeze_pos = 3)
///   squeeze_bytes_n::<10>()
///
/// Returns the 10-byte output spongefish would produce after the same
/// preparation.
pub fn squeeze_bytes_kat_expected() -> [u8; 10] {
    let state = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
    ];
    // Lane-unit absorb_pos = 1 -> byte absorb_pos = 1 * 32 = 32.
    // Lane-unit squeeze_pos = 3 -> byte squeeze_pos = 3 * 32 = 96 (RATE
    // boundary; first byte squeeze triggers a permute, matching the Noir
    // wrapper which calls the inner Sponge that permutes when
    // `squeeze_pos == RATE`).
    let bytes = byte_sponge_replay(state, 32, 96, 10);
    let mut out = [0u8; 10];
    out.copy_from_slice(&bytes);
    out
}

/// Tensor product of two Fr vectors, row-major. Used to cross-validate Noir's
/// tensor_product.
pub fn tensor_product_kat_expected() -> [Fr; 4] {
    let a = [Fr::from(2u64), Fr::from(3u64)];
    let b = [Fr::from(5u64), Fr::from(7u64)];
    let mut result = [Fr::from(0u64); 4];
    for i in 0..2 {
        for j in 0..2 {
            result[i * 2 + j] = a[i] * b[j];
        }
    }
    result
}

/// Multilinear extension evaluation at a point. Used to cross-validate
/// Noir's mle_evaluate.
pub fn mle_evaluate_kat_expected() -> Fr {
    let one = Fr::from(1u64);
    let a0 = Fr::from(2u64);
    let a1 = Fr::from(3u64);
    let eq = [
        (one - a0) * (one - a1), //  2
        (one - a0) * a1,         // -3
        a0 * (one - a1),         // -4
        a0 * a1,                 //  6
    ];
    let coeffs = [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let mut acc = Fr::from(0u64);
    for i in 0..4 {
        acc += coeffs[i] * eq[i];
    }
    acc
}

/// Replay the commitment-receive sequence in Rust: fresh sponge, absorb
/// root then OOD evals, squeeze 1 challenge. Returns the squeezed challenge.
pub fn commitment_receive_kat_expected() -> Fr {
    // Fresh transcript = lane sponge with state=[0;4], absorb_pos=0, squeeze_pos=3 (RATE).
    let state = [Fr::from(0u64); 4];
    let absorb_pos: u32 = 0;
    let squeeze_pos: u32 = 3;
    let absorbs = [Fr::from(100u64), Fr::from(200u64), Fr::from(300u64)];
    let squeezes = lane_sponge_replay(state, absorb_pos, squeeze_pos, &absorbs, 1);
    squeezes[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Print the four field elements that Noir's
    /// `EXPECTED_PERMUTE_1234` global should hold. Run with `--nocapture`
    /// to capture them; paste into `verifier-noir/src/poseidon2.nr` in
    /// step 4 below.
    #[test]
    fn print_kat_expected_for_noir() {
        let expected = kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_PERMUTE_1234[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the four field elements that Noir's `EXPECTED_SPONGE_KAT`
    /// global should hold. Run with `--nocapture` to capture them.
    #[test]
    fn print_sponge_kat_expected_for_noir() {
        let expected = sponge_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_SPONGE_KAT[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the two field elements that Noir's `EXPECTED_TRANSCRIPT_KAT`
    /// global should hold.
    #[test]
    fn print_transcript_kat_expected_for_noir() {
        let expected = transcript_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_TRANSCRIPT_KAT[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the field element that Noir's `EXPECTED_HASH_2` global should
    /// hold.
    #[test]
    fn print_merkle_kat_expected_for_noir() {
        let expected = merkle_kat_expected();
        println!("EXPECTED_HASH_2 = {}", fr_to_noir_literal(expected));
    }

    /// Print the four field elements that Noir's `EXPECTED_A_AT_ALPHA` global
    /// should hold. Run with `--nocapture` to capture them; paste into
    /// `verifier-noir/src/matrix_eval.nr`.
    #[test]
    fn print_matrix_eval_kat_expected_for_noir() {
        let expected = matrix_eval_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_A_AT_ALPHA[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the values that Noir's sumcheck KAT globals should hold.
    #[test]
    fn print_sumcheck_kat_expected_for_noir() {
        let (h_polys, f_at_alpha) = sumcheck_kat_construct();
        for (round, row) in h_polys.iter().enumerate() {
            for (j, c) in row.iter().enumerate() {
                println!(
                    "SUMCHECK_KAT_H_POLYS[{round}][{j}] = {}",
                    fr_to_noir_literal(*c)
                );
            }
        }
        println!(
            "EXPECTED_SUMCHECK_F_AT_ALPHA = {}",
            fr_to_noir_literal(f_at_alpha)
        );
    }

    #[test]
    fn print_public_input_kat_expected_for_noir() {
        let dst = public_inputs_dst_fe();
        println!("PUBLIC_INPUTS_DST_FE = {}", fr_to_noir_literal(dst));
        let hash = public_input_kat_expected();
        println!("EXPECTED_PI_HASH = {}", fr_to_noir_literal(hash));
    }

    #[test]
    fn print_merkle_path_kat_expected_for_noir() {
        let (siblings, root) = merkle_path_kat_expected();
        println!(
            "EXPECTED_PATH_SIBLINGS[0] = {}",
            fr_to_noir_literal(siblings[0])
        );
        println!(
            "EXPECTED_PATH_SIBLINGS[1] = {}",
            fr_to_noir_literal(siblings[1])
        );
        println!("EXPECTED_PATH_ROOT = {}", fr_to_noir_literal(root));
    }

    #[test]
    fn print_geometric_challenge_kat_expected_for_noir() {
        let expected = geometric_challenge_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!(
                "EXPECTED_GEOMETRIC_CHALLENGE[{i}] = {}",
                fr_to_noir_literal(*fe)
            );
        }
    }

    /// Print the 10 bytes that Noir's `EXPECTED_SQUEEZE_BYTES_KAT` global
    /// should hold. Run with `--nocapture` to capture them; paste into
    /// `verifier-noir/src/transcript.nr`.
    #[test]
    fn print_squeeze_bytes_kat_expected_for_noir() {
        let expected = squeeze_bytes_kat_expected();
        let joined: Vec<String> = expected.iter().map(|b| b.to_string()).collect();
        println!("EXPECTED_SQUEEZE_BYTES_KAT = [{}]", joined.join(", "));
    }

    #[test]
    fn print_commitment_receive_kat_expected_for_noir() {
        let chal = commitment_receive_kat_expected();
        println!("EXPECTED_RECEIVE_CHALLENGE = {}", fr_to_noir_literal(chal));
    }

    /// Spongefish equivalence sanity check: when we squeeze 32-byte aligned
    /// chunks, our byte-grain replay must agree with `lane_sponge_replay`'s
    /// LE-encoded field output on the same starting state.
    #[test]
    fn byte_replay_agrees_with_lane_replay_on_aligned_squeezes() {
        let state = [
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        // Squeeze 2 whole lanes worth of bytes (64 bytes) and compare to
        // squeezing 2 fields and encoding each LE.
        let bytes = byte_sponge_replay(state, 32, 96, 64);
        let fields = lane_sponge_replay(state, 1, 3, &[], 2);
        let mut expected = Vec::with_capacity(64);
        expected.extend_from_slice(&fr_to_le_bytes(fields[0]));
        expected.extend_from_slice(&fr_to_le_bytes(fields[1]));
        assert_eq!(
            bytes, expected,
            "byte/lane replays disagree on aligned squeeze"
        );
    }
}
