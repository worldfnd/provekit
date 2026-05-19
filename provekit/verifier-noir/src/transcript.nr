//! High-level Fiat-Shamir transcript over the lane-oriented Poseidon2 sponge.
//!
//! Mirrors the API the Rust verifier uses against spongefish (`absorb_field`,
//! `squeeze_field`), plus an `init_from_pre_absorbed_state` entry point that
//! receives the sponge state computed Rust-side after the domain separator
//! and the `instance` bytes have been absorbed.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/transcript_kat.rs`.

use crate::sponge::Sponge;

pub struct Transcript {
    sponge: Sponge,
}

impl Transcript {
    /// Fresh transcript (sponge at all-zero initial state).
    pub fn new() -> Self {
        Self { sponge: Sponge::new() }
    }

    /// Initialize from the Rust codegen tool's pre-absorbed state.
    ///
    /// The codegen tool replays the spongefish protocol-id + instance absorbs
    /// against `Poseidon2Sponge::default()`, then exports the resulting
    /// (state, absorb_pos, squeeze_pos) triple as private witness for the
    /// verifier circuit. From this point on, every absorb/squeeze is
    /// field-grain and the lane-oriented sponge is faithful.
    pub fn init_from_pre_absorbed_state(
        state: [Field; 4],
        absorb_pos: u32,
        squeeze_pos: u32,
    ) -> Self {
        Self { sponge: Sponge::from_state(state, absorb_pos, squeeze_pos) }
    }

    pub fn absorb_field(&mut self, fe: Field) {
        self.sponge.absorb_field(fe);
    }

    pub fn squeeze_field(&mut self) -> Field {
        self.sponge.squeeze_field()
    }

    /// Squeeze a challenge `x` and return its first `N` powers: [1, x, x^2, ..., x^(N-1)].
    /// Used by WHIR for vector / constraint random linear combination coefficients.
    /// Matches `whir::protocols::geometric_challenge::geometric_challenge`.
    pub fn geometric_challenge<let N: u32>(&mut self) -> [Field; N] {
        let x = self.squeeze_field();
        let mut result: [Field; N] = [0; N];
        // N is compile-time; if N == 0, the loop is empty and we return [].
        if N > 0 {
            result[0] = 1;
            for i in 1..N {
                result[i] = result[i-1] * x;
            }
        }
        result
    }
}

// --- in-circuit KAT ---
//
// Canonical Phase 1B transcript KAT sequence:
//   init_from_pre_absorbed_state(state = [10, 20, 30, 40], absorb_pos = 1, squeeze_pos = 3)
//   absorb_field(7); absorb_field(8)
//   squeeze_field() -> a
//   squeeze_field() -> b
// EXPECTED_TRANSCRIPT_KAT freezes [a, b]. Task 4 replaces the placeholder.
//
// Values computed by the lane-grain sponge replay over the canonical KAT
// sequence; frozen as a KAT. See provekit/verifier-noir-test/tests/transcript_kat.rs
// for the cross-impl guarantee.
global EXPECTED_TRANSCRIPT_KAT: [Field; 2] = [
    12128367233918472140666042190034498091224706939667107265017613623179249826679,
    18318138449124604570938096546205124296708170073712695146954402082885284978251,
];

#[test]
fn transcript_init_absorb_squeeze_matches_frozen_kat() {
    let mut t = Transcript::init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3);
    t.absorb_field(7);
    t.absorb_field(8);
    let a = t.squeeze_field();
    let b = t.squeeze_field();
    assert([a, b] == EXPECTED_TRANSCRIPT_KAT);
}

// --- in-circuit geometric_challenge KAT (placeholder) ---
//
// Canonical sequence:
//   transcript = init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3)
//   geometric_challenge::<4>() -> [1, x, x^2, x^3]
// EXPECTED_GEOMETRIC_CHALLENGE freezes the 4-element result.
//
// Values computed by the Rust lane-grain transcript replay starting from
// the canonical state ([10,20,30,40], 1, 3): 4 powers of the squeezed
// challenge. Frozen as a KAT; see
// provekit/verifier-noir-test/tests/geometric_challenge_kat.rs for the
// cross-impl guarantee.
global EXPECTED_GEOMETRIC_CHALLENGE: [Field; 4] = [
    1,
    430982174079281787229464968551228484657529710645573398135735974095608036650,
    19625818251407731757584666141922939846101842500419009550749541162485484034641,
    13496892432355821020771877310159633017841692662012349923596342671263624293281,
];

#[test]
fn geometric_challenge_matches_frozen_kat() {
    let mut t = Transcript::init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3);
    let powers = t.geometric_challenge::<4>();
    assert(powers == EXPECTED_GEOMETRIC_CHALLENGE);
}
