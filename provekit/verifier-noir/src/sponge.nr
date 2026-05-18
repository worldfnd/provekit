//! Lane-oriented duplex sponge over BN254 Poseidon2.
//!
//! Mirrors spongefish's `DuplexSponge<Poseidon2Wrapper, 128, 96>` byte-for-byte
//! when every absorb / squeeze aligns to 32-byte (1-lane) boundaries - which
//! is the case for every operation in ProveKit's WHIR transcript after the
//! domain separator. Pre-domain-separator absorbs are computed Rust-side
//! and shipped as `pre_absorbed_state` to the verifier circuit.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/sponge_kat.rs`.

use crate::poseidon2::permute;

global RATE: u32 = 3; // 3 field lanes = 96 bytes
global WIDTH: u32 = 4; // 4 field lanes = 128 bytes (RATE + capacity)

/// Duplex sponge state. RATE = 3 lanes, capacity = 1 lane (state[3]).
pub struct Sponge {
    pub state: [Field; 4],
    pub absorb_pos: u32,
    pub squeeze_pos: u32,
}

impl Sponge {
    /// Fresh sponge: all-zero state. squeeze_pos starts at RATE so the first
    /// squeeze permutes (matches spongefish's initial state).
    pub fn new() -> Self {
        Self { state: [0, 0, 0, 0], absorb_pos: 0, squeeze_pos: RATE }
    }

    /// Initialize from a Rust-side pre-absorbed state (domain separator +
    /// instance already absorbed). Caller must ensure (state, absorb_pos,
    /// squeeze_pos) come from a faithful spongefish replay.
    pub fn from_state(state: [Field; 4], absorb_pos: u32, squeeze_pos: u32) -> Self {
        assert(absorb_pos <= RATE);
        assert(squeeze_pos <= RATE);
        Self { state, absorb_pos, squeeze_pos }
    }

    /// Absorb one field element (= 32 bytes when serialized LE).
    /// Matches spongefish's absorb path at lane granularity.
    pub fn absorb_field(&mut self, fe: Field) {
        // Reset squeeze mode (spongefish line 198).
        self.squeeze_pos = RATE;

        // Permute on rate overflow (spongefish lines 201-203).
        if self.absorb_pos == RATE {
            self.state = permute(self.state);
            self.absorb_pos = 0;
        }

        // Overwrite the current rate lane (spongefish line 209).
        self.state[self.absorb_pos] = fe;
        self.absorb_pos = self.absorb_pos + 1;
    }

    /// Squeeze one field element. Permutes if the rate has been fully drained
    /// (matches spongefish lines 224-227).
    pub fn squeeze_field(&mut self) -> Field {
        // Reset absorb mode (spongefish line 222).
        self.absorb_pos = 0;

        if self.squeeze_pos == RATE {
            self.squeeze_pos = 0;
            self.state = permute(self.state);
        }

        let out = self.state[self.squeeze_pos];
        self.squeeze_pos = self.squeeze_pos + 1;
        out
    }
}

// --- in-circuit KAT ---
//
// EXPECTED_SPONGE_KAT freezes the four squeezed outputs after the canonical
// sequence: new() -> absorb_field(1) -> absorb_field(2) -> 4 x squeeze_field().
// Task 2 (Phase 1B) replaces this with the real values computed by spongefish.
//
// PLACEHOLDER VALUE - overwritten in Phase 1B Task 2 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_SPONGE_KAT: [Field; 4] = [0, 0, 0, 0];

#[test]
fn sponge_absorb_squeeze_matches_frozen_kat() {
    let mut s = Sponge::new();
    s.absorb_field(1);
    s.absorb_field(2);
    let a = s.squeeze_field();
    let b = s.squeeze_field();
    let c = s.squeeze_field();
    let d = s.squeeze_field();
    assert([a, b, c, d] == EXPECTED_SPONGE_KAT);
}
