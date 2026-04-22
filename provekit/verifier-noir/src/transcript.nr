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
    /// rate is exhausted. The Noir compiler CSEs the repeated
    /// `field_to_bytes_le(state[lane])` calls within the loop body into
    /// one decomposition per lane, so no explicit fast path is needed.
    pub fn squeeze_32_bytes(&mut self) -> [u8; 32] {
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

    /// Advance the sponge's squeeze state by `n` bytes without materializing
    /// them. Semantics: identical final `(state, absorb_pos, squeeze_pos)` to
    /// calling `squeeze_1` `n` times and discarding every return.
    ///
    /// Callers MUST NOT rely on the discarded bytes. Intended for transcript
    /// advances (STIR challenge indices) where the bytes are consumed by the
    /// Rust-side Fiat-Shamir protocol purely to derive challenge indices;
    /// the in-circuit verifier verifies those indices via Merkle proofs, not
    /// by re-deriving from bytes.
    ///
    /// Uses chunked advance bounded to 4 iterations (enough for up to
    /// ~384 bytes); caller asserts its `n` is within that bound.
    pub fn advance_squeeze_bytes(&mut self, n: u32) {
        self.absorb_pos = 0;

        let mut remaining = n;
        for _ in 0..4 {
            if remaining > 0 {
                if self.squeeze_pos == RATE_BYTES {
                    self.do_permute();
                    self.squeeze_pos = 0;
                }
                let avail = RATE_BYTES - self.squeeze_pos;
                let take = if avail < remaining { avail } else { remaining };
                self.squeeze_pos += take;
                remaining -= take;
            }
        }
        // Defensive: assert we consumed everything. For n <= 384 this always
        // holds since 4 iterations of up to 96 bytes = 384.
        assert(remaining == 0, "advance_squeeze_bytes: n exceeds 4-chunk bound");
    }

    /// Absorb raw bytes into the sponge.
    ///
    /// Used for: protocol_id, instance, PoW nonces. Two paths:
    ///   - Fast: when the next 32 bytes land on an aligned rate lane with no
    ///     bytes needing preservation, compose the new field element directly
    ///     from the input bytes (no decomposition of state).
    ///   - Slow: single-byte path that decomposes the current lane, overwrites
    ///     one byte, and recomposes. Required for mid-lane/partial writes
    ///     where existing bytes of the lane must be preserved (e.g. the
    ///     trailing bytes of a lane after an 8-byte PoW nonce absorb).
    pub fn absorb_bytes<let N: u32>(&mut self, input: [u8; N]) {
        self.squeeze_pos = RATE_BYTES;

        let mut i: u32 = 0;
        // Upper bound: if every step takes the slow (1-byte) path, we run N
        // iterations; fast-path iterations consume 32 bytes but the loop
        // bound must still cover the worst case.
        for _ in 0..N {
            if i < N as u32 {
                if self.absorb_pos == RATE_BYTES {
                    self.do_permute();
                    self.absorb_pos = 0;
                }

                let offset = self.absorb_pos % 32;
                let lane = self.absorb_pos / 32;
                let rem_input = N as u32 - i;

                if (offset == 0) & (rem_input >= 32) {
                    // Fast path: compose one full rate lane from input bytes.
                    // No decomposition of state[lane] required because we
                    // overwrite all 32 bytes.
                    let mut acc: Field = 0;
                    for j in 0..32 {
                        acc += (input[i + j] as Field) * crate::types::POW256[j];
                    }
                    self.state[lane] = acc;
                    self.absorb_pos += 32;
                    i += 32;
                } else {
                    // Slow path: decompose, overwrite one byte, recompose.
                    let mut lane_bytes = field_to_bytes_le(self.state[lane]);
                    lane_bytes[offset] = input[i];
                    self.state[lane] = bytes_le_to_field(lane_bytes);
                    self.absorb_pos += 1;
                    i += 1;
                }
            }
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

// =========================================================================
// Tests
// =========================================================================

#[test]
fn absorb_bytes_aligned_full_lane_matches_field_absorb() {
    // Absorbing 32 aligned bytes as bytes should produce identical state to
    // absorbing the same bytes composed as a field element.
    let bytes: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let mut a = Sponge::new();
    a.absorb_bytes(bytes);
    let mut b = Sponge::new();
    b.absorb_field(bytes_le_to_field(bytes));
    assert(a.state[0] == b.state[0]);
    assert(a.state[1] == b.state[1]);
    assert(a.state[2] == b.state[2]);
    assert(a.state[3] == b.state[3]);
    assert(a.absorb_pos == b.absorb_pos);
}

#[test]
fn absorb_bytes_two_full_lanes_matches_two_field_absorbs() {
    // 64 bytes at absorb_pos=0 -> two full lanes, all fast-path.
    let bytes: [u8; 64] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];
    let mut a = Sponge::new();
    a.absorb_bytes(bytes);
    let mut first: [u8; 32] = [0; 32];
    let mut second: [u8; 32] = [0; 32];
    for i in 0..32 {
        first[i] = bytes[i];
        second[i] = bytes[32 + i];
    }
    let mut b = Sponge::new();
    b.absorb_field(bytes_le_to_field(first));
    b.absorb_field(bytes_le_to_field(second));
    assert(a.state[0] == b.state[0]);
    assert(a.state[1] == b.state[1]);
    assert(a.state[2] == b.state[2]);
    assert(a.state[3] == b.state[3]);
    assert(a.absorb_pos == b.absorb_pos);
}

#[test]
fn absorb_bytes_slow_path_8_bytes_at_lane_0() {
    // Exercises the slow byte-by-byte path (rem_input < 32). Fresh sponge
    // has zero state, so after writing 8 bytes at lane 0 offsets 0..8 the
    // remaining bytes 8..32 of lane 0 stay zero.
    let small: [u8; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
    let mut a = Sponge::new();
    a.absorb_bytes(small);

    let mut expected: Field = 0;
    for i in 0..8 {
        expected += (small[i] as Field) * crate::types::POW256[i];
    }
    assert(a.state[0] == expected);
    assert(a.state[1] == 0);
    assert(a.state[2] == 0);
    assert(a.state[3] == 0);
    assert(a.absorb_pos == 8);
}

#[test]
fn advance_squeeze_matches_byte_by_byte_254() {
    // Seed both sponges identically.
    let seed: [u8; 64] = [
        7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
        197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 15,
    ];
    let mut a = Sponge::new();
    a.absorb_bytes(seed);
    let _force_squeeze_mode: Field = a.squeeze_field();

    let mut b = Sponge::new();
    b.absorb_bytes(seed);
    let _force_squeeze_mode_b: Field = b.squeeze_field();

    // A: batched advance.
    a.advance_squeeze_bytes(254);
    // B: byte-by-byte.
    for _ in 0..254 {
        let _byte = b.squeeze_1();
    }

    assert(a.state[0] == b.state[0]);
    assert(a.state[1] == b.state[1]);
    assert(a.state[2] == b.state[2]);
    assert(a.state[3] == b.state[3]);
    assert(a.squeeze_pos == b.squeeze_pos);
    assert(a.absorb_pos == b.absorb_pos);
}

#[test]
fn advance_squeeze_matches_byte_by_byte_exact_rate() {
    // Advance exactly 96 bytes from squeeze_pos=0 - boundary case, no permute yet.
    let mut a = Sponge::new();
    let _f: Field = a.squeeze_field();
    // After squeeze_field, squeeze_pos = 64 (8 bytes into lane 2).
    // Actually Sponge::new sets squeeze_pos=RATE, squeeze_field will permute once
    // then advance by 64. So squeeze_pos = 64 now.
    let mut b = Sponge::new();
    let _f2: Field = b.squeeze_field();

    a.advance_squeeze_bytes(96);
    for _ in 0..96 {
        let _byte = b.squeeze_1();
    }

    assert(a.state[0] == b.state[0]);
    assert(a.state[1] == b.state[1]);
    assert(a.state[2] == b.state[2]);
    assert(a.state[3] == b.state[3]);
    assert(a.squeeze_pos == b.squeeze_pos);
}

#[test]
fn absorb_bytes_96_spans_all_rate_lanes() {
    // Absorbing exactly one full rate (3 lanes) ends at absorb_pos == 96,
    // ready to trigger a permute on the next absorb.
    let bytes: [u8; 96] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
        72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
        95, 96,
    ];
    let mut a = Sponge::new();
    a.absorb_bytes(bytes);

    let mut l0: [u8; 32] = [0; 32];
    let mut l1: [u8; 32] = [0; 32];
    let mut l2: [u8; 32] = [0; 32];
    for i in 0..32 {
        l0[i] = bytes[i];
        l1[i] = bytes[32 + i];
        l2[i] = bytes[64 + i];
    }
    assert(a.state[0] == bytes_le_to_field(l0));
    assert(a.state[1] == bytes_le_to_field(l1));
    assert(a.state[2] == bytes_le_to_field(l2));
    assert(a.state[3] == 0);
    assert(a.absorb_pos == 96);
}
