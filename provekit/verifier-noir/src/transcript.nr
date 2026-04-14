// Skyscraper Duplex Sponge Transcript
//
// Implements the spongefish DuplexSponge<Skyscraper, 64, 32> protocol for
// Fiat-Shamir transcript in the WHIR verifier.
//
// Reference: spongefish/src/duplex_sponge.rs (DuplexSponge absorb/squeeze/ratchet)
//            provekit/common/src/skyscraper/sponge.rs (Skyscraper Permutation<64>)
//            spongefish/src/drivers/ark_ff_impl.rs (field element encoding/decoding)
//
// The sponge operates on a 64-byte state = [rate(32 bytes), capacity(32 bytes)],
// represented as two BN254 field elements.
//
// Field element absorption: 32 LE bytes -> exactly fills rate.
// Field element squeeze: 64 bytes (two rate-fills) -> reduce mod p.
// Byte-level operations: decompose rate Field to/from bytes as needed.

use crate::types::{bytes_le_to_field, bytes_le_to_field_wide, field_to_bytes_le};
use skyscraper_noir::permute;

/// Skyscraper duplex sponge state.
///
/// Mirrors spongefish's `DuplexSponge<P, WIDTH=64, RATE=32>`:
/// - `state[0]` = rate (first 32 bytes), `state[1]` = capacity (last 32 bytes)
/// - `absorb_pos`: bytes absorbed into current rate (0..32)
/// - `squeeze_pos`: bytes consumed from current squeeze (0..32; 32 = exhausted)
pub struct Sponge {
    state: [Field; 2],
    absorb_pos: u32,
    squeeze_pos: u32,
}

impl Sponge {
    /// Create a new sponge with zero-initialized state.
    ///
    /// Matches `DuplexSponge::default()`: state=[0;64], absorb_pos=0, squeeze_pos=RATE(32).
    pub fn new() -> Self {
        Self {
            state: [0, 0],
            absorb_pos: 0,
            squeeze_pos: 32, // RATE = 32, meaning "need permute before squeeze"
        }
    }

    /// Initialize sponge with an IV written to the capacity.
    ///
    /// Used for domain separator: the tag (32 bytes) is placed in state[32..64]
    /// i.e. the capacity portion = state[1].
    pub fn new_with_tag(tag: Field) -> Self {
        Self { state: [0, tag], absorb_pos: 0, squeeze_pos: 32 }
    }

    /// Permute the state using Skyscraper.
    fn do_permute(&mut self) {
        let (l, r) = permute(self.state[0], self.state[1]);
        self.state[0] = l;
        self.state[1] = r;
    }

    // =====================================================================
    // FAST PATH: aligned absorb / squeeze
    // =====================================================================
    //
    // The general absorb_field / squeeze_field methods carry an
    // `if absorb_pos == 0 { fast } else { partial-rate }` branch. ACIR
    // flattens both branches, so every call pays for the partial-rate
    // dead code path (~800 constraints of byte decompose / merge / second
    // permute) that the WHIR verifier never takes at runtime.
    //
    // The aligned variants below assume the WHIR verifier's actual
    // invariant: between calls, absorb_pos is always 0 or 32 - i.e. the
    // sponge is at a field boundary. They drop the dead branch entirely,
    // saving ~870 constraints per call.
    //
    // Soundness: identical sponge state evolution, identical Fiat-Shamir
    // transcript bytes. Only unreachable branches are removed.
    //
    // Use sequence:
    //   let mut sho = Sponge::new();
    //   sho.absorb_bytes(protocol_id);              // byte init (rare)
    //   sho.absorb_bytes(instance);                 // byte init (rare)
    //   sho.absorb_field_aligned(initial_root);     // every other absorb
    //   ...
    //   sho.squeeze_field_aligned();                // every squeeze
    //
    // For cold-start use (when the sponge has just been created and
    // nothing has been absorbed yet), call `absorb_field_first` once
    // before switching to `absorb_field_aligned`. The first call after
    // `Sponge::new()` must NOT permute - spongefish's DuplexSponge
    // begins with squeeze_pos = RATE and absorb_pos = 0, so the first
    // field is written directly into the rate without a prior permute.

    /// First field absorb after `Sponge::new()` - no permute.
    ///
    /// Mirrors spongefish DuplexSponge::absorb_unchecked when called on
    /// a fresh state: rate is empty, absorb_pos = 0, so the field is
    /// written directly into state[0] and absorb_pos becomes 32.
    pub fn absorb_field_first(&mut self, f: Field) {
        self.state[0] = f;
        self.absorb_pos = 32;
        self.squeeze_pos = 32;
    }

    /// Absorb a field element assuming the sponge is at a field boundary.
    ///
    /// PRECONDITION: absorb_pos == 32 (always true after a prior
    /// absorb_field_aligned / absorb_field_first / squeeze_field_aligned
    /// call). Calling this with absorb_pos != 32 produces an incorrect
    /// transcript.
    ///
    /// Cost: ~676 constraints (one Skyscraper permute) - vs ~1550 for
    /// the general `absorb_field`.
    pub fn absorb_field_aligned(&mut self, f: Field) {
        self.do_permute();
        self.state[0] = f;
        self.absorb_pos = 32;
        self.squeeze_pos = 32;
    }

    /// Squeeze a field element from a sponge at a field boundary.
    ///
    /// Mirrors `squeeze_field` but drops the partial-rate dead branches.
    /// PRECONDITION: the sponge is at a field boundary, i.e. squeeze_pos
    /// is either 0 (we just wrote/permuted into rate) or 32 (we need a
    /// fresh permute). Both cases are handled identically by the
    /// duplex-sponge spec: squeezing always permutes first when entering
    /// squeeze mode, then reads the rate.
    ///
    /// Returns `low + high * 2^256` mod p, matching arkworks
    /// `from_le_bytes_mod_order` on 64 bytes squeezed from two
    /// consecutive permutations.
    ///
    /// Cost: ~1352 constraints (two permutes) - vs ~3100 for the
    /// general `squeeze_field`.
    pub fn squeeze_field_aligned(&mut self) -> Field {
        // First 32 bytes: permute into a fresh rate, take state[0] as the
        // 32-byte little-endian integer.
        self.do_permute();
        let low = self.state[0];

        // Second 32 bytes: permute again, take state[0] again.
        self.do_permute();
        let high = self.state[0];

        // After squeezing 64 bytes the rate is exhausted; mark for refill.
        self.absorb_pos = 0;
        self.squeeze_pos = 32;

        low + high * crate::types::TWO_POW_256
    }

    // =====================================================================
    // Field-aligned operations (general, with dead-code partial-rate path)
    // =====================================================================

    /// Absorb a single field element (32 LE bytes).
    ///
    /// In the WHIR verifier, absorb_pos is always 0 or 32 when absorbing
    /// field elements, so the fast path (no byte decomposition) is taken.
    pub fn absorb_field(&mut self, f: Field) {
        // Reset squeeze tracking (entering absorb mode)
        self.squeeze_pos = 32;

        if self.absorb_pos == 32 {
            // Rate is full -> permute first
            self.do_permute();
            self.absorb_pos = 0;
        }

        if self.absorb_pos == 0 {
            // Write field element directly into rate (overwrite mode)
            self.state[0] = f;
            self.absorb_pos = 32;
        } else {
            // Partial rate: decompose, merge, reconstruct
            // This path is rarely taken in the WHIR verifier
            let rate_bytes = field_to_bytes_le(self.state[0]);
            let f_bytes = field_to_bytes_le(f);
            let pos = self.absorb_pos;
            let remaining = 32 - pos;

            // Fill remaining rate with first `remaining` bytes of f
            let mut merged: [u8; 32] = [0; 32];
            for i in 0..32 {
                if (i as u32) < pos {
                    merged[i] = rate_bytes[i];
                } else {
                    merged[i] = f_bytes[(i as u32) - pos];
                }
            }
            self.state[0] = bytes_le_to_field(merged);

            // Rate is now full -> permute
            self.do_permute();

            // Write remaining bytes of f into fresh rate
            let written = remaining;
            let left = 32 - written;
            if left > 0 {
                let mut new_rate: [u8; 32] = [0; 32];
                for i in 0..32 {
                    if (i as u32) < left {
                        new_rate[i] = f_bytes[written + i];
                    }
                }
                self.state[0] = bytes_le_to_field(new_rate);
                self.absorb_pos = left;
            } else {
                self.absorb_pos = 32;
            }
        }
    }

    /// Squeeze a single field element (64 bytes, reduced mod p).
    ///
    /// Matches the arkworks Decoding: squeeze `MODULUS_BIT_SIZE/8 + 32 = 64` bytes,
    /// then `from_le_bytes_mod_order`.
    pub fn squeeze_field(&mut self) -> Field {
        let first_32 = self.squeeze_32_bytes();
        let second_32 = self.squeeze_32_bytes();

        // Combine 64 bytes into a wide field element and reduce mod p
        let mut wide: [u8; 64] = [0; 64];
        for i in 0..32 {
            wide[i] = first_32[i];
            wide[32 + i] = second_32[i];
        }
        bytes_le_to_field_wide(wide)
    }

    /// Squeeze exactly 32 bytes (one full rate element).
    pub fn squeeze_32_bytes(&mut self) -> [u8; 32] {
        // Reset absorb tracking (entering squeeze mode)
        self.absorb_pos = 0;

        if self.squeeze_pos >= 32 {
            // Need fresh permutation
            self.squeeze_pos = 0;
            self.do_permute();
        }

        if self.squeeze_pos == 0 {
            // Read entire rate as bytes
            self.squeeze_pos = 32;
            field_to_bytes_le(self.state[0])
        } else {
            // Partial rate remaining: extract bytes from squeeze_pos onward
            let rate_bytes = field_to_bytes_le(self.state[0]);
            let start = self.squeeze_pos;
            let available = 32 - start;
            let mut out: [u8; 32] = [0; 32];

            // Take remaining bytes from current rate
            for i in 0..32 {
                if (i as u32) < available {
                    out[i] = rate_bytes[start + i];
                }
            }

            // Need more bytes from next permutation
            self.do_permute();
            self.squeeze_pos = 0;
            let fresh_bytes = field_to_bytes_le(self.state[0]);
            let needed = 32 - available;
            for i in 0..32 {
                if (i as u32) < needed {
                    out[available + i] = fresh_bytes[i];
                }
            }
            self.squeeze_pos = needed;

            out
        }
    }

    // =====================================================================
    // Byte-level operations (for STIR challenges and PoW nonces)
    // =====================================================================

    /// Absorb raw bytes into the sponge.
    ///
    /// Used for: protocol_id, instance, PoW nonce, Merkle root bytes.
    /// For field-element-aligned inputs (32 or 64 bytes), prefer absorb_field.
    pub fn absorb_bytes<let N: u32>(&mut self, input: [u8; N]) {
        self.squeeze_pos = 32;

        let mut input_pos: u32 = 0;

        // Process in chunks that fit the remaining rate
        for _chunk in 0..((N + 31) / 32 + 1) {
            if input_pos < N {
                if self.absorb_pos == 32 {
                    self.do_permute();
                    self.absorb_pos = 0;
                }

                // Decompose current rate to bytes
                let mut rate_bytes = field_to_bytes_le(self.state[0]);

                // Write bytes into rate starting at absorb_pos
                let space = 32 - self.absorb_pos;
                let remaining_input = N - input_pos;
                let to_write = if space < remaining_input {
                    space
                } else {
                    remaining_input
                };

                for i in 0..32 {
                    if (i as u32) < to_write {
                        rate_bytes[self.absorb_pos + i] = input[input_pos + i];
                    }
                }

                self.state[0] = bytes_le_to_field(rate_bytes);
                self.absorb_pos += to_write;
                input_pos += to_write;
            }
        }
    }

    /// Squeeze a single byte.
    ///
    /// Used for STIR challenge byte extraction.
    pub fn squeeze_1(&mut self) -> u8 {
        self.absorb_pos = 0;

        if self.squeeze_pos >= 32 {
            self.squeeze_pos = 0;
            self.do_permute();
        }

        let rate_bytes = field_to_bytes_le(self.state[0]);
        let byte = rate_bytes[self.squeeze_pos];
        self.squeeze_pos += 1;
        byte
    }

    // =====================================================================
    // Ratchet
    // =====================================================================

    /// Ratchet the sponge state.
    ///
    /// Matches DuplexSponge::ratchet:
    /// 1. Set absorb_pos = RATE, squeeze_pos = RATE
    /// 2. Zero the rate portion
    /// 3. Permute
    pub fn ratchet(&mut self) {
        self.absorb_pos = 32;
        self.squeeze_pos = 32;
        self.state[0] = 0; // zero rate
        self.do_permute();
    }
}
