//! WHIR low-degree-test verifier.
//!
//! Phase 3B-iv: scaffold + PoW verifier stub.
//! The full WHIR LDT verifier (commitment, sumcheck loop, query phase,
//! final claim) lands in subsequent Phase 3B sub-tasks.

use crate::transcript::Transcript;

/// Stub PoW verifier. Verifies the proof's PoW nonce against the
/// transcript's challenge. For v0/basic-2 with difficulty = 0, this is
/// effectively a no-op; the prover supplies any 32-byte hint and we
/// absorb it into the transcript.
///
/// TODO: real PoW verification once the difficulty bits per round are
/// surfaced from the WHIR scheme via codegen.
pub fn verify_pow_stub(transcript: &mut Transcript, nonce: Field) {
    // Absorb the nonce into the transcript so any tampering changes
    // downstream challenges. For real PoW we would also derive a challenge
    // from squeeze_bytes_n and check H(challenge || nonce) has D trailing
    // zero bits.
    transcript.absorb_field(nonce);
}

// Trivial smoke test: stub absorbs without panicking.
#[test]
fn verify_pow_stub_smoke() {
    let mut t = Transcript::new();
    verify_pow_stub(&mut t, 42);
    // The stub never asserts; test passes if it returns.
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
