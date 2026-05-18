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

global RATE: u32 = 3; // 3 field lanes = 96 bytes (capacity is the remaining lane, state[3])

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
        // Entering absorb mode: force a permute before the next squeeze
        // (spongefish line 198).
        self.squeeze_pos = RATE;

        // Permute on rate overflow (spongefish lines 201-203).
        if self.absorb_pos == RATE {
            self.state = permute(self.state);
            self.absorb_pos = 0;
        }

        // Overwrite the current rate lane (spongefish line 209).
        self.state[self.absorb_pos] = fe;
        self.absorb_pos += 1;
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
        self.squeeze_pos += 1;
        out
    }
}

// --- in-circuit KAT ---
//
// EXPECTED_SPONGE_KAT freezes the four squeezed outputs after the canonical
// sequence: new() -> absorb_field(1) -> absorb_field(2) -> 4 x squeeze_field().
//
// Values computed by spongefish's Poseidon2Sponge over the canonical KAT
// sequence; frozen as a KAT. See provekit/verifier-noir-test/tests/sponge_kat.rs
// for the cross-impl guarantee.
global EXPECTED_SPONGE_KAT: [Field; 4] = [
    18820432867059154094859436055199616701968052823097718648623846518936613856822,
    18765307673170827115753326813900875002848140270017525397879152595142186698156,
    8902268457968403723723455777528503219317767098362558216701468192393217466553,
    6893255428283411714874654770501629555921995326027890220762013361906424133476,
];

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
