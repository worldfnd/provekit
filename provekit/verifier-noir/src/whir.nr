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
