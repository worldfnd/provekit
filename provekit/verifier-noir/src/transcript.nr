// Poseidon2 Duplex Sponge Transcript
//
// Implements the spongefish DuplexSponge<Poseidon2Wrapper, 128, 96> protocol
// for Fiat-Shamir transcript in the WHIR verifier.
//
// Reference: spongefish/src/duplex_sponge.rs (DuplexSponge absorb/squeeze/ratchet)
//            provekit/common/src/poseidon2/sponge.rs (Poseidon2 Permutation<128>)
//            spongefish/src/drivers/ark_ff_impl.rs (field element encoding/decoding)
//
// State layout (128 bytes = 4 BN254 field elements):
//   state[0..3] = rate   (96 bytes = 3 field elements)
//   state[3]    = capacity (32 bytes = 1 field element)
//
// Field element absorption: 32 LE bytes = one rate lane.
// Field element squeeze:    64 bytes (2 lanes) reduced mod p.
// Byte-level operations:    decompose/recompose one lane at a time.
//
// Invariant used by the fast path: when `absorb_field` is called from the
// WHIR verifier, `absorb_pos` is a multiple of 32 (ensured by the fact that
// preceding squeezes always reset `absorb_pos` to 0 and subsequent field
// absorbs advance by 32). This lets us write the field element directly
// into the appropriate rate lane without byte decomposition.

use crate::types::{bytes_le_to_field, bytes_le_to_field_wide, field_to_bytes_le};
use std::hash::poseidon2_permutation;

global RATE_BYTES: u32 = 96;

/// Poseidon2 duplex sponge state.
///
/// Mirrors spongefish's `DuplexSponge<Poseidon2Wrapper, WIDTH=128, RATE=96>`:
/// - state[0..3] are the three rate lanes, state[3] is the capacity lane
/// - `absorb_pos`:  bytes absorbed into the current rate (0..96)
/// - `squeeze_pos`: bytes consumed from the current squeeze (0..96;
///                  96 = "rate exhausted, need permute before next squeeze")
pub struct Sponge {
    state: [Field; 4],
    absorb_pos: u32,
    squeeze_pos: u32,
}

impl Sponge {
    /// Create a new sponge with zero-initialized state.
    ///
    /// Matches `DuplexSponge::default()`: state=[0;128], absorb_pos=0,
    /// squeeze_pos=RATE(96). Domain separation is performed by absorbing
    /// the domain-separator bytes (protocol_id || instance) first, matching
    /// how the Rust `VerifierState::new` constructs its initial transcript.
    pub fn new() -> Self {
        Self { state: [0, 0, 0, 0], absorb_pos: 0, squeeze_pos: RATE_BYTES }
    }

    /// Permute the state using Poseidon2 (BN254, t=4).
    fn do_permute(&mut self) {
        self.state = poseidon2_permutation(self.state, 4);
    }

    // =====================================================================
    // Field-level operations
    // =====================================================================

    /// Absorb a single field element (32 LE bytes).
    ///
    /// Fast path assumes `absorb_pos` is a multiple of 32 (the invariant
    /// held by the WHIR verifier). A field element lands in one rate lane;
    /// when the rate is full, a permutation is triggered.
    pub fn absorb_field(&mut self, f: Field) {
        // Reset squeeze tracking (entering absorb mode)
        self.squeeze_pos = RATE_BYTES;

        if self.absorb_pos == RATE_BYTES {
            self.do_permute();
            self.absorb_pos = 0;
        }

        // absorb_pos in {0, 32, 64} -> lane in {0, 1, 2}
        let lane = self.absorb_pos / 32;
        self.state[lane] = f;
        self.absorb_pos += 32;
    }

    /// Absorb a field element at a known rate boundary (alias for `absorb_field`).
    ///
    /// For Poseidon2 with rate=3, a "field boundary" is not the same as a
    /// "rate boundary" (3 field absorbs fill one rate). The general
    /// `absorb_field` already takes the direct-lane-write fast path, so no
    /// separate implementation is needed.
    pub fn absorb_field_aligned(&mut self, f: Field) {
        self.absorb_field(f)
    }

    /// Squeeze a single field element (64 bytes, reduced mod p).
    ///
    /// Matches the arkworks Decoding: squeeze 64 bytes and
    /// `from_le_bytes_mod_order`. With rate=96, 64 bytes of squeeze may
    /// be taken from a single permutation (squeeze_pos 0..64) or span
    /// the rate/next-permute boundary.
    pub fn squeeze_field(&mut self) -> Field {
        let first_32 = self.squeeze_32_bytes();
        let second_32 = self.squeeze_32_bytes();
        let mut wide: [u8; 64] = [0; 64];
        for i in 0..32 {
            wide[i] = first_32[i];
            wide[32 + i] = second_32[i];
        }
        bytes_le_to_field_wide(wide)
    }

    /// Squeeze a field element (alias for `squeeze_field`).
    pub fn squeeze_field_aligned(&mut self) -> Field {
        self.squeeze_field()
    }

    // =====================================================================
    // Byte-level operations (for STIR challenges, PoW nonces, and the
    // initial protocol_id / instance absorb)
    // =====================================================================

    /// Squeeze exactly 32 bytes.
    ///
    /// Walks one byte at a time across rate lanes, permuting when the
    /// rate is exhausted. Correct for any starting `squeeze_pos`.
    pub fn squeeze_32_bytes(&mut self) -> [u8; 32] {
        // Reset absorb tracking (entering squeeze mode)
        self.absorb_pos = 0;

        let mut out: [u8; 32] = [0; 32];
        for i in 0..32 {
            if self.squeeze_pos == RATE_BYTES {
                self.do_permute();
                self.squeeze_pos = 0;
            }
            let lane = self.squeeze_pos / 32;
            let lane_offset = self.squeeze_pos % 32;
            let lane_bytes = field_to_bytes_le(self.state[lane]);
            out[i] = lane_bytes[lane_offset];
            self.squeeze_pos += 1;
        }
        out
    }

    /// Squeeze a single byte.
    pub fn squeeze_1(&mut self) -> u8 {
        self.absorb_pos = 0;

        if self.squeeze_pos == RATE_BYTES {
            self.do_permute();
            self.squeeze_pos = 0;
        }

        let lane = self.squeeze_pos / 32;
        let lane_offset = self.squeeze_pos % 32;
        let lane_bytes = field_to_bytes_le(self.state[lane]);
        let byte = lane_bytes[lane_offset];
        self.squeeze_pos += 1;
        byte
    }

    /// Absorb raw bytes into the sponge.
    ///
    /// Used for: protocol_id, instance, PoW nonces. Walks byte-by-byte
    /// across rate lanes, decomposing/recomposing the affected lane. For
    /// field-element-aligned inputs prefer `absorb_field`.
    pub fn absorb_bytes<let N: u32>(&mut self, input: [u8; N]) {
        self.squeeze_pos = RATE_BYTES;

        for i in 0..N {
            if self.absorb_pos == RATE_BYTES {
                self.do_permute();
                self.absorb_pos = 0;
            }

            let lane = self.absorb_pos / 32;
            let lane_offset = self.absorb_pos % 32;
            let mut lane_bytes = field_to_bytes_le(self.state[lane]);
            lane_bytes[lane_offset] = input[i];
            self.state[lane] = bytes_le_to_field(lane_bytes);
            self.absorb_pos += 1;
        }
    }

    // =====================================================================
    // Ratchet
    // =====================================================================

    /// Ratchet the sponge state.
    ///
    /// Matches DuplexSponge::ratchet:
    /// 1. Set absorb_pos = RATE, squeeze_pos = RATE
    /// 2. Zero the rate portion (all three rate lanes)
    /// 3. Permute
    pub fn ratchet(&mut self) {
        self.absorb_pos = RATE_BYTES;
        self.squeeze_pos = RATE_BYTES;
        self.state[0] = 0;
        self.state[1] = 0;
        self.state[2] = 0;
        self.do_permute();
    }
}
