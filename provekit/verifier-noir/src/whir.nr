//! WHIR low-degree-test verifier.
//!
//! Phase 3B-vi: real BLAKE3-based PoW verifier replacing the stub.

use crate::transcript::Transcript;
use std::hash::blake3;

/// Verify a Blake3-based PoW: assert that BLAKE3(challenge || nonce || pad)
/// has its first 8 bytes (as u64 LE) less than or equal to `threshold`.
///
/// `challenge` is the 32 bytes the verifier squeezed from the transcript at
/// PoW verification time. `nonce_bytes` is the prover-supplied u64 encoded
/// as 8 little-endian bytes. `threshold` is `ceil(2^(64 - difficulty_bits))`.
///
/// Matches `whir::protocols::proof_of_work::Config::verify` (0aeaa7f):
///   input  = challenge[0..32] || nonce_le[0..8] || [0u8; 24]  // 64 bytes
///   hash   = BLAKE3(input)
///   result = u64::from_le_bytes(hash[0..8])
///   verify: result <= threshold
///
/// After the hash check the nonce is absorbed into the transcript as a
/// field element (8 LE bytes zero-padded to 32) so downstream challenges
/// depend on the PoW result, matching WHIR's `prover_message(&U64(nonce))`.
pub fn verify_pow(
    transcript: &mut Transcript,
    nonce_bytes: [u8; 8],
    threshold: u64,
) {
    // Squeeze the 32-byte PoW challenge from the transcript (matches
    // `verifier_state.verifier_message::<[u8; 32]>()`).
    let challenge: [u8; 32] = transcript.squeeze_bytes_n::<32>();

    // Build the 64-byte BLAKE3 input: challenge || nonce_le || zeros[24].
    let mut input: [u8; 64] = [0; 64];
    for i in 0..32 {
        input[i] = challenge[i];
    }
    for i in 0..8 {
        input[32 + i] = nonce_bytes[i];
    }
    // Bytes 40..64 remain zero (zero-extension to a full BLAKE3 block).

    // Compute BLAKE3 of the 64-byte input.
    let hash: [u8; 32] = blake3(input);

    // Extract first 8 bytes as u64 LE and assert <= threshold.
    let mut hash_lo: u64 = 0;
    for i in 0..8 {
        hash_lo += (hash[i] as u64) * pow2_u64(i);
    }
    assert(hash_lo <= threshold);

    // Absorb the nonce into the transcript as a field element (8 LE bytes
    // zero-padded to 32), matching WHIR's `prover_message(&U64(nonce))`.
    let mut nonce_field: Field = 0;
    for i in 0..8 {
        nonce_field += (nonce_bytes[i] as Field) * pow2_field(8 * i);
    }
    transcript.absorb_field(nonce_field);
}

/// Compute `256^byte_index` as u64 (i.e. `1 << (8 * byte_index)`).
/// Used to build a u64 from individual bytes in little-endian order.
fn pow2_u64(byte_index: u32) -> u64 {
    let mut result: u64 = 1;
    for _ in 0..byte_index {
        result *= 256;
    }
    result
}

/// Compute `2^bit_index` as Field.
/// Used to build a Field element from individual bits.
fn pow2_field(bit_index: u32) -> Field {
    let mut result: Field = 1;
    for _ in 0..bit_index {
        result *= 2;
    }
    result
}

// --- in-circuit PoW KAT ---
//
// Canonical sequence:
//   transcript = init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3)
//   verify_pow(transcript, EXPECTED_NONCE_BYTES, EXPECTED_THRESHOLD_8BITS)
// Difficulty: 8 bits, threshold = 2^56 = 72057594037927936.
// The Rust helper (pow_kat_expected in provekit-verifier-noir-test) finds the
// smallest nonce satisfying the check for the squeezed challenge.
global EXPECTED_NONCE_BYTES: [u8; 8] = [11, 2, 0, 0, 0, 0, 0, 0];
global EXPECTED_THRESHOLD_8BITS: u64 = 72057594037927936; // 2^56

#[test]
fn verify_pow_matches_frozen_kat() {
    let mut t = crate::transcript::Transcript::init_from_pre_absorbed_state(
        [10, 20, 30, 40], 1, 3,
    );
    verify_pow(&mut t, EXPECTED_NONCE_BYTES, EXPECTED_THRESHOLD_8BITS);
    // If we reach here, the PoW check passed.
}

/// Commitment received from the prover: a Merkle root and a fixed number
/// of out-of-domain (OOD) evaluations.
pub struct Commitment<let OOD_COUNT: u32> {
    pub root: Field,
    pub ood_evals: [Field; OOD_COUNT],
}

/// Absorb a commitment into the transcript: root first, then each OOD eval
/// in order. Matches `whir::protocols::irs_commit::Committer::receive_commitment`.
pub fn receive_commitment<let OOD_COUNT: u32>(
    transcript: &mut crate::transcript::Transcript,
    commitment: Commitment<OOD_COUNT>,
) {
    transcript.absorb_field(commitment.root);
    for i in 0..OOD_COUNT {
        transcript.absorb_field(commitment.ood_evals[i]);
    }
}

// --- in-circuit commitment receive KAT ---
//
// Canonical sequence:
//   transcript = Transcript::new()
//   commitment = { root: 100, ood_evals: [200, 300] }
//   receive_commitment(&mut t, commitment)
//   challenge = t.squeeze_field()  // verify the absorb desync would change this
//
// EXPECTED_RECEIVE_CHALLENGE freezes the post-absorb squeezed challenge.
global EXPECTED_RECEIVE_CHALLENGE: Field = 15482865631404602010586643531248511548722443393982267905029295042944073245539;

#[test]
fn receive_commitment_matches_frozen_kat() {
    let mut t = crate::transcript::Transcript::new();
    let commitment = Commitment::<2> {
        root: 100,
        ood_evals: [200, 300],
    };
    receive_commitment::<2>(&mut t, commitment);
    let challenge = t.squeeze_field();
    assert(challenge == EXPECTED_RECEIVE_CHALLENGE);
}
