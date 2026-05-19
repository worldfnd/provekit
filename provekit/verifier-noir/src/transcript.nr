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

// Approach A (chosen): byte buffer wrapper around the existing lane-grain Sponge.
//
// Rationale: the existing `Sponge` KAT (lane-grain) stays untouched, and the
// byte-grain extension lives entirely in `Transcript`. Spongefish's underlying
// state is `[u8; 128]` with squeeze_pos in 0..96, but every absorb our verifier
// does is field-grain (32-byte aligned), so the byte buffer only ever needs to
// track *squeezed* bytes mid-lane. We squeeze whole field elements from the
// inner sponge on demand and slice off the leading LE bytes; when the buffer
// drains, we squeeze the next field element.
//
// Equivalence to spongefish: when spongefish squeezes N bytes, the bytes are
// `field_to_bytes_le(state[lane])[byte_offset..]` for the current lane, then
// the next lane, etc. By squeezing one field at a time from the inner sponge
// (advancing `squeeze_pos` by 1 lane each time, with a permute on RATE
// overflow) and decoding it via `to_le_bytes::<32>()`, we get the exact same
// byte stream spongefish would emit.
//
// IMPORTANT: callers MUST NOT mix byte-grain (`squeeze_bytes_n`) and
// field-grain (`squeeze_field`) without understanding the interaction. After
// a byte squeeze leaves a partial lane in the buffer, the next `squeeze_field`
// will discard the buffer (resetting alignment) and squeeze a fresh field
// from the inner sponge, matching spongefish's "entering a new mode" reset.

pub struct Transcript {
    sponge: Sponge,
    // Byte-level squeeze buffer: holds the unread suffix of the most recently
    // squeezed field element, decoded as 32 little-endian bytes.
    byte_buf: [u8; 32],
    // Number of valid (unread) bytes in `byte_buf`, starting at byte_buf[32 - byte_buf_len].
    byte_buf_len: u32,
}

impl Transcript {
    /// Fresh transcript (sponge at all-zero initial state).
    pub fn new() -> Self {
        Self { sponge: Sponge::new(), byte_buf: [0; 32], byte_buf_len: 0 }
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
        Self {
            sponge: Sponge::from_state(state, absorb_pos, squeeze_pos),
            byte_buf: [0; 32],
            byte_buf_len: 0,
        }
    }

    pub fn absorb_field(&mut self, fe: Field) {
        // Entering absorb mode invalidates any leftover squeezed bytes
        // (mirrors spongefish entering absorb mode, which moves on past any
        // partial squeezed lane).
        self.byte_buf_len = 0;
        self.sponge.absorb_field(fe);
    }

    pub fn squeeze_field(&mut self) -> Field {
        // A field-grain squeeze discards any leftover bytes from a prior
        // partial byte squeeze. Spongefish's lane-grain reads always advance
        // to the next whole lane, so leftover sub-lane bytes are gone.
        self.byte_buf_len = 0;
        self.sponge.squeeze_field()
    }

    /// Squeeze N raw bytes from the transcript, byte-for-byte equivalent to
    /// spongefish squeezing N bytes after the same input sequence.
    ///
    /// Endianness: we decode each squeezed Field element via
    /// `Field::to_le_bytes::<32>()` (little-endian). This matches spongefish's
    /// `field_to_bytes_le`. WHIR's PoW verifier and query-index sampling read
    /// raw bytes in this canonical LE encoding.
    ///
    /// Strategy:
    ///   - If the byte buffer has bytes left from a prior partial-lane
    ///     squeeze, drain those first.
    ///   - Otherwise, squeeze a fresh field from the inner sponge, decode it
    ///     to 32 LE bytes, and refill the buffer. The first byte of a fresh
    ///     lane is `byte_buf[0]`; bytes are consumed left-to-right.
    pub fn squeeze_bytes_n<let N: u32>(&mut self) -> [u8; N] {
        let mut out: [u8; N] = [0; N];
        for i in 0..N {
            if self.byte_buf_len == 0 {
                // Need a fresh lane: squeeze one field and refill the buffer.
                // NOTE: We call the inner sponge directly (not self.squeeze_field)
                // because self.squeeze_field() would zero `byte_buf_len`, which
                // is what we want -- but it would also discard the buffer we are
                // about to populate. Calling the inner sponge keeps the buffer
                // semantics owned by this method.
                let fe = self.sponge.squeeze_field();
                let lane: [u8; 32] = fe.to_le_bytes();
                self.byte_buf = lane;
                self.byte_buf_len = 32;
            }
            // Next byte to consume is at position (32 - byte_buf_len).
            let pos = 32 - self.byte_buf_len;
            out[i] = self.byte_buf[pos];
            self.byte_buf_len -= 1;
        }
        out
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
                result[i] = result[i - 1] * x;
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

// --- in-circuit byte-squeeze KAT ---
//
// Canonical sequence:
//   transcript = init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3)
//   squeeze_bytes_n::<10>() -> 10 bytes
//
// EXPECTED_SQUEEZE_BYTES_KAT freezes the first 10 bytes that spongefish would
// produce starting from the byte-equivalent state (lanes [10, 20, 30, 40]
// encoded LE into 128 bytes, absorb_pos = 32, squeeze_pos = 96). Because
// squeeze_pos starts at the RATE boundary (96), the first byte read triggers
// a permute, then we slice LE bytes off the first squeezed lane.
//
// Computed by `provekit_verifier_noir_test::squeeze_bytes_kat_expected`
// (Rust byte-grain replay). The cross-impl KAT in
// `provekit/verifier-noir-test/tests/squeeze_bytes_kat.rs` regenerates these.
global EXPECTED_SQUEEZE_BYTES_KAT: [u8; 10] = [42, 61, 23, 44, 165, 41, 24, 59, 46, 161];

#[test]
fn squeeze_bytes_matches_frozen_kat() {
    let mut t = Transcript::init_from_pre_absorbed_state([10, 20, 30, 40], 1, 3);
    let bytes = t.squeeze_bytes_n::<10>();
    assert(bytes == EXPECTED_SQUEEZE_BYTES_KAT);
}
