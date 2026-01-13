//! SIMD-optimized BLAKE3 batch compression for Merkle trees.
//!
//! This module provides hardware-accelerated batch hashing using BLAKE3's
//! internal SIMD capabilities. It can hash multiple messages in parallel,
//! significantly improving Merkle tree construction performance.
//!
//! Adapted from merkle-hash-bench implementation.

use blake3::{
    guts::{BLOCK_LEN, CHUNK_LEN},
    platform::{Platform, MAX_SIMD_DEGREE},
    IncrementCounter, OUT_LEN,
};

// Static assertions to ensure BLAKE3 constants match our expectations
const _: () = assert!(
    OUT_LEN == 32,
    "BLAKE3 compression output does not equal hash size."
);
const _: () = assert!(
    BLOCK_LEN == 2 * 32,
    "BLAKE3 compression input does not equal a pair of hashes."
);
const _: () = assert!(
    CHUNK_LEN == 16 * BLOCK_LEN,
    "BLAKE3 chunk len is not 16 blocks."
);

/// Default BLAKE3 initialization vector.
const BLAKE3_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Flags for a single block message.
const FLAGS_START: u8 = 1 << 0; // CHUNK_START
const FLAGS_END: u8 = 1 << 1; // CHUNK_END
const FLAGS: u8 = 1 << 3; // ROOT

/// SIMD-optimized BLAKE3 batch hasher for Merkle tree compression.
///
/// This hasher uses the detected platform's SIMD capabilities to hash
/// multiple messages in parallel, up to `MAX_SIMD_DEGREE` at a time.
pub struct Blake3Simd {
    platform: Platform,
}

impl Blake3Simd {
    /// Create a new SIMD-optimized BLAKE3 hasher.
    ///
    /// Automatically detects the best available SIMD implementation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            platform: Platform::detect(),
        }
    }

    /// Returns a string describing the detected platform implementation.
    #[must_use]
    pub fn implementation(&self) -> String {
        format!("{:?}", self.platform)
    }

    /// Returns the maximum SIMD degree (number of parallel hashes).
    #[must_use]
    pub const fn max_simd_degree() -> usize {
        MAX_SIMD_DEGREE
    }

    /// Batch compress multiple 64-byte messages into 32-byte hashes.
    ///
    /// This is optimized for Merkle tree internal node hashing where
    /// we compress pairs of 32-byte digests.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `inputs.len()` is not a multiple of 64
    /// - `outputs.len()` is not a multiple of 32
    /// - `inputs.len() / 64 != outputs.len() / 32`
    pub fn compress_many(&self, inputs: &[u8], outputs: &mut [u8]) {
        assert_eq!(inputs.len() % 64, 0, "Input size must be a multiple of 64");
        assert_eq!(
            outputs.len() % 32,
            0,
            "Output size must be a multiple of 32"
        );
        assert_eq!(
            inputs.len() / 64,
            outputs.len() / 32,
            "Input/output count mismatch"
        );

        self.hash_many_const::<{ BLOCK_LEN }>(inputs, outputs);
    }

    /// Internal method for constant-size message hashing.
    fn hash_many_const<const N: usize>(&self, inputs: &[u8], output: &mut [u8]) {
        // Cast the input to a slice of N-sized arrays
        let inputs = as_chunks_exact::<u8, N>(inputs);

        // Process up to MAX_SIMD_DEGREE messages in parallel
        for (inputs, out) in inputs
            .chunks(MAX_SIMD_DEGREE)
            .zip(output.chunks_mut(OUT_LEN * MAX_SIMD_DEGREE))
        {
            // Construct an array of references to input messages
            let inputs: arrayvec::ArrayVec<&[u8; N], MAX_SIMD_DEGREE> =
                inputs.iter().collect();

            // Hash the messages in parallel using SIMD
            self.platform.hash_many::<N>(
                &inputs,
                &BLAKE3_IV,
                0,
                IncrementCounter::No,
                FLAGS,
                FLAGS_START,
                FLAGS_END,
                out,
            );
        }
    }

    /// Hash variable-size messages (up to 16 blocks = 1024 bytes each).
    ///
    /// # Panics
    ///
    /// Panics if message size exceeds `CHUNK_LEN` (1024 bytes).
    pub fn hash_many(&self, inputs: &[u8], output: &mut [u8], message_size: usize) {
        assert!(
            message_size % BLOCK_LEN == 0,
            "Message size must be a multiple of the block length ({BLOCK_LEN})."
        );
        assert!(
            message_size <= CHUNK_LEN,
            "Message size must not exceed a single chunk ({CHUNK_LEN})."
        );
        assert!(
            inputs.len() % message_size == 0,
            "Input size must be a multiple of the message size."
        );
        assert!(
            output.len() % 32 == 0,
            "Output size must be a multiple of the hash size."
        );
        assert_eq!(
            output.len() / 32,
            inputs.len() / message_size,
            "Output size mismatch."
        );

        let blocks = message_size / BLOCK_LEN;

        // Dispatch to the appropriate constant-size implementation
        match blocks {
            0 => {}
            1 => self.hash_many_const::<{ BLOCK_LEN }>(inputs, output),
            2 => self.hash_many_const::<{ 2 * BLOCK_LEN }>(inputs, output),
            3 => self.hash_many_const::<{ 3 * BLOCK_LEN }>(inputs, output),
            4 => self.hash_many_const::<{ 4 * BLOCK_LEN }>(inputs, output),
            5 => self.hash_many_const::<{ 5 * BLOCK_LEN }>(inputs, output),
            6 => self.hash_many_const::<{ 6 * BLOCK_LEN }>(inputs, output),
            7 => self.hash_many_const::<{ 7 * BLOCK_LEN }>(inputs, output),
            8 => self.hash_many_const::<{ 8 * BLOCK_LEN }>(inputs, output),
            9 => self.hash_many_const::<{ 9 * BLOCK_LEN }>(inputs, output),
            10 => self.hash_many_const::<{ 10 * BLOCK_LEN }>(inputs, output),
            11 => self.hash_many_const::<{ 11 * BLOCK_LEN }>(inputs, output),
            12 => self.hash_many_const::<{ 12 * BLOCK_LEN }>(inputs, output),
            13 => self.hash_many_const::<{ 13 * BLOCK_LEN }>(inputs, output),
            14 => self.hash_many_const::<{ 14 * BLOCK_LEN }>(inputs, output),
            15 => self.hash_many_const::<{ 15 * BLOCK_LEN }>(inputs, output),
            16 => self.hash_many_const::<{ 16 * BLOCK_LEN }>(inputs, output),
            _ => unreachable!("Invalid block count."),
        }
    }
}

impl Default for Blake3Simd {
    fn default() -> Self {
        Self::new()
    }
}

/// Cast a slice into chunks of size N.
///
/// # Panics
///
/// Panics if the slice length is not a multiple of N.
fn as_chunks_exact<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    assert!(N != 0, "chunk size must be non-zero");
    assert_eq!(
        slice.len() % N,
        0,
        "slice length must be a multiple of chunk size"
    );
    let new_len = slice.len() / N;
    // SAFETY: We verified that the slice length is a multiple of N
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast(), new_len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_many() {
        let hasher = Blake3Simd::new();
        println!("Using implementation: {}", hasher.implementation());

        // Test with 4 pairs of 32-byte inputs
        let inputs = vec![0xABu8; 64 * 4];
        let mut outputs = vec![0u8; 32 * 4];

        hasher.compress_many(&inputs, &mut outputs);

        // Verify outputs are non-zero and different from input pattern
        assert!(outputs.iter().any(|&b| b != 0xAB));
        assert!(outputs.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_single_compress() {
        let hasher = Blake3Simd::new();

        let input = [0u8; 64];
        let mut output = [0u8; 32];

        hasher.compress_many(&input, &mut output);

        // Compare with standard blake3 hash
        let expected: [u8; 32] = blake3::hash(&input).into();
        assert_eq!(output, expected, "SIMD compress must match standard blake3::hash");
    }
}
