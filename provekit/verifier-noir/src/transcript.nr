// Spongefish SHA256 Stateful Hash Object (SHO)
//
// Faithful Noir reimplementation of spongefish's Hash<sha2::Sha256>.
// See: spongefish/src/instantiations/hash.rs
//
// The SHO state machine:
//   Start --absorb--> Absorb --ratchet/squeeze--> Start
//   Start --squeeze--> Squeeze --squeeze_end--> Start
//
// Key invariant: every byte absorbed/squeezed here MUST match the Rust
// spongefish implementation exactly. Any divergence invalidates all
// Fiat-Shamir challenges.

use crate::types::{
    SHA256_INIT, SHA256_DIGEST_SIZE,
    field_to_bytes_le, bytes_le_to_field_wide, u64_to_be_bytes,
};
use std::hash::sha256_compression;

// --- Streaming SHA256 Hasher ---
//
// Noir's sha256_compression is a single-block primitive. We build a
// streaming Merkle-Damgard SHA256 on top of it.

// Maximum bytes we can accumulate before finalization.
// Must be large enough for the biggest absorb session:
//   mask(64) + cv(32) + data (bounded by IO pattern)
// 2048 bytes = 32 SHA256 blocks -- generous for any verifier session.
pub global MAX_BUF: u32 = 512;

// Maximum number of SHA256 blocks we process (MAX_BUF / 64 + 1 for padding).
global MAX_BLOCKS: u32 = 9; // ceil(MAX_BUF / 64) + 1

pub struct StreamingSha256 {
    state: [u32; 8],
    buf: [u8; MAX_BUF],
    buf_len: u32,
}

// Convert 64 bytes to 16 big-endian u32 words, reading from a buffer at offset.
fn buf_to_words(buf: [u8; MAX_BUF], base: u32) -> [u32; 16] {
    let mut words: [u32; 16] = [0; 16];
    for i in 0..16 {
        let off = base + (i as u32) * 4;
        words[i] = ((buf[off] as u32) << 24)
            | ((buf[off + 1] as u32) << 16)
            | ((buf[off + 2] as u32) << 8)
            | (buf[off + 3] as u32);
    }
    words
}

// Convert 64 bytes from a [u8; 128] at offset to 16 u32 words.
fn pad_to_words(data: [u8; 128], offset: u32) -> [u32; 16] {
    let mut words: [u32; 16] = [0; 16];
    for i in 0..16 {
        let off = offset + (i as u32) * 4;
        words[i] = ((data[off] as u32) << 24)
            | ((data[off + 1] as u32) << 16)
            | ((data[off + 2] as u32) << 8)
            | (data[off + 3] as u32);
    }
    words
}

impl StreamingSha256 {
    fn new() -> Self {
        StreamingSha256 {
            state: SHA256_INIT,
            buf: [0; MAX_BUF],
            buf_len: 0,
        }
    }

    // Reset to initial state.
    fn reset(&mut self) {
        self.state = SHA256_INIT;
        self.buf = [0; MAX_BUF];
        self.buf_len = 0;
    }

    // Append bytes to the internal buffer.
    fn update<let N: u32>(&mut self, data: [u8; N]) {
        for i in 0..N {
            self.buf[self.buf_len + i] = data[i];
        }
        self.buf_len += N;
    }

    // Finalize: pad and process all remaining blocks. Returns the 32-byte digest.
    fn finalize(self) -> [u8; 32] {
        let total_bits: u64 = (self.buf_len as u64) * 8;

        // Process complete blocks already in the buffer
        let full_blocks = self.buf_len / 64;
        let mut state = self.state;
        for i in 0..MAX_BLOCKS {
            if (i as u32) < full_blocks {
                let block = buf_to_words(self.buf, (i as u32) * 64);
                state = sha256_compression(block, state);
            }
        }

        // Remaining bytes after complete blocks
        let remaining = self.buf_len - full_blocks * 64;

        // Build the final padded block(s)
        // Padding: append 0x80, then zeros, then 8-byte big-endian bit length
        let mut pad_buf: [u8; 128] = [0; 128]; // at most 2 blocks for padding
        let base = full_blocks * 64;
        for i in 0..64 {
            if (i as u32) < remaining {
                pad_buf[i] = self.buf[base + i as u32];
            }
        }
        pad_buf[remaining] = 0x80;

        // If remaining + 1 + 8 > 64, we need two padding blocks
        let need_two_blocks = (remaining + 9) > 64;

        if need_two_blocks {
            // Length goes at end of second block
            let len_bytes = u64_to_be_bytes(total_bits);
            for i in 0..8 {
                pad_buf[120 + i] = len_bytes[i];
            }
            let block1 = pad_to_words(pad_buf, 0);
            let block2 = pad_to_words(pad_buf, 64);
            state = sha256_compression(block1, state);
            state = sha256_compression(block2, state);
        } else {
            // Length goes at end of single block
            let len_bytes = u64_to_be_bytes(total_bits);
            for i in 0..8 {
                pad_buf[56 + i] = len_bytes[i];
            }
            let block = pad_to_words(pad_buf, 0);
            state = sha256_compression(block, state);
        }

        // Convert state to big-endian bytes
        let mut out: [u8; 32] = [0; 32];
        for i in 0..8 {
            out[4 * i]     = ((state[i] >> 24) & 0xFF) as u8;
            out[4 * i + 1] = ((state[i] >> 16) & 0xFF) as u8;
            out[4 * i + 2] = ((state[i] >> 8) & 0xFF) as u8;
            out[4 * i + 3] = (state[i] & 0xFF) as u8;
        }
        out
    }

    // Clone this hasher's current state for squeeze operations.
    // Uses value semantics (copy) since Noir doesn't have references.
    fn copy(self) -> StreamingSha256 {
        let mut cloned = StreamingSha256::new();
        cloned.state = self.state;
        cloned.buf = self.buf;
        cloned.buf_len = self.buf_len;
        cloned
    }
}

// --- Mask Blocks ---
//
// The SHO uses 64-byte (SHA256 block size) mask blocks to separate
// absorb, squeeze, and squeeze_end operations.
//
// mask_absorb:     [0x00; 63] ++ [0x00]  (all zeros, last byte 0x00)
// mask_squeeze:    [0x00; 63] ++ [0x01]
// mask_squeeze_end:[0x00; 63] ++ [0x02]

fn mask_absorb() -> [u8; 64] {
    let mut m: [u8; 64] = [0; 64];
    m[63] = 0x00;
    m
}

fn mask_squeeze() -> [u8; 64] {
    let mut m: [u8; 64] = [0; 64];
    m[63] = 0x01;
    m
}

fn mask_squeeze_end() -> [u8; 64] {
    let mut m: [u8; 64] = [0; 64];
    m[63] = 0x02;
    m
}

// --- SHO State Machine ---

global MODE_START: u8 = 0;
global MODE_ABSORB: u8 = 1;
global MODE_SQUEEZE: u8 = 2;

pub struct SHO {
    cv: [u8; 32],
    hasher: StreamingSha256,
    mode: u8,
    squeeze_counter: u32,
    leftovers: [u8; 32],
    leftovers_len: u32,
}

impl SHO {
    // Create a new SHO with default initial state.
    pub fn new() -> Self {
        SHO {
            cv: [0; 32],
            hasher: StreamingSha256::new(),
            mode: MODE_START,
            squeeze_counter: 0,
            leftovers: [0; 32],
            leftovers_len: 0,
        }
    }

    // Absorb a fixed-size byte array into the sponge.
    //
    // Implements spongefish Hash::absorb():
    //   if mode == Start:
    //     update(mask_absorb)
    //     update(cv)
    //     mode = Absorb
    //   update(data)
    pub fn absorb<let N: u32>(&mut self, data: [u8; N]) {
        self.squeeze_end_if_squeezing();

        if self.mode == MODE_START {
            self.mode = MODE_ABSORB;
            self.hasher.update(mask_absorb());
            self.hasher.update(self.cv);
        }

        self.hasher.update(data);
    }

    // Absorb a single field element (32 bytes little-endian).
    pub fn absorb_field(&mut self, f: Field) {
        let bytes = field_to_bytes_le(f);
        self.absorb(bytes);
    }

    // Ratchet: double-hash the accumulated state and reset.
    //
    // cv = SHA256(SHA256(accumulated))
    // Reset hasher and mode.
    pub fn ratchet(&mut self) {
        self.squeeze_end_if_squeezing();

        // First hash: finalize accumulated data
        let inner = self.hasher.finalize();

        // Second hash: SHA256(inner)
        let mut outer_hasher = StreamingSha256::new();
        outer_hasher.update(inner);
        self.cv = outer_hasher.finalize();

        // Reset
        self.hasher.reset();
        self.leftovers = [0; 32];
        self.leftovers_len = 0;
        self.mode = MODE_START;
    }

    // Squeeze exactly 32 bytes from the sponge.
    //
    // Implements the squeeze logic from spongefish Hash::squeeze():
    //   if mode == Start:
    //     update(mask_squeeze)
    //     update(cv)
    //     mode = Squeeze(0)
    //   if mode == Absorb:
    //     ratchet() first, then squeeze
    //   Clone hasher, append counter, finalize -> 32 bytes
    pub fn squeeze_32(&mut self) -> [u8; 32] {
        // If absorbing, ratchet first
        if self.mode == MODE_ABSORB {
            self.ratchet();
        }

        // If starting fresh squeeze
        if self.mode == MODE_START {
            self.mode = MODE_SQUEEZE;
            self.squeeze_counter = 0;
            self.hasher.update(mask_squeeze());
            self.hasher.update(self.cv);
        }

        // If we have leftovers from a previous squeeze chunk, use them
        if self.leftovers_len > 0 {
            let mut out: [u8; 32] = [0; 32];
            for i in 0..32 {
                if (i as u32) < self.leftovers_len {
                    out[i] = self.leftovers[i];
                }
            }
            self.leftovers_len = 0;
            self.leftovers = [0; 32];
            out
        } else {
            // Squeeze a fresh 32-byte chunk
            let mut clone = self.hasher.copy();
            let counter_bytes = u64_to_be_bytes(self.squeeze_counter as u64);
            clone.update(counter_bytes);
            let digest = clone.finalize();

            self.squeeze_counter += 1;
            digest
        }
    }

    // Squeeze a field element: squeeze 64 bytes, reduce mod BN254 scalar.
    //
    // Spongefish squeezes MODULUS_BIT_SIZE.div_ceil(8) + 32 = 64 bytes
    // for uniform field element sampling. The 64 bytes are interpreted
    // as a little-endian integer and reduced mod p via from_le_bytes_mod_order.
    pub fn squeeze_field(&mut self) -> Field {
        let low = self.squeeze_32();
        let high = self.squeeze_32();
        let mut wide: [u8; 64] = [0; 64];
        for i in 0..32 {
            wide[i] = low[i];
            wide[32 + i] = high[i];
        }
        bytes_le_to_field_wide(wide)
    }

    // Internal: if we're in squeeze mode, finalize it.
    //
    // squeeze_end(): cv = SHA256(mask_squeeze_end || old_cv || byte_count)
    fn squeeze_end_if_squeezing(&mut self) {
        if self.mode == MODE_SQUEEZE {
            self.hasher.reset();

            // Compute how many bytes were actually read from squeezes
            let byte_count: u64 = (self.squeeze_counter as u64) * (SHA256_DIGEST_SIZE as u64)
                - (self.leftovers_len as u64);

            // cv = SHA256(mask_squeeze_end || old_cv || byte_count.to_be_bytes())
            let mut sq_hasher = StreamingSha256::new();
            sq_hasher.update(mask_squeeze_end());
            sq_hasher.update(self.cv);
            let count_bytes = u64_to_be_bytes(byte_count);
            sq_hasher.update(count_bytes);
            self.cv = sq_hasher.finalize();

            // Reset
            self.mode = MODE_START;
            self.leftovers = [0; 32];
            self.leftovers_len = 0;
        }
    }

    // Explicitly end a squeeze session (public API matching spongefish).
    pub fn squeeze_end(&mut self) {
        self.squeeze_end_if_squeezing();
    }
}
