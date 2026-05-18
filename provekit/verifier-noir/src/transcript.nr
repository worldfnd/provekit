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
