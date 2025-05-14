use {
    crate::{register_hash, HashFn, SmolHasher},
    arrayvec::ArrayVec,
    blake3::{
        guts::{BLOCK_LEN, CHUNK_LEN},
        platform::{Platform, MAX_SIMD_DEGREE},
        IncrementCounter, OUT_LEN,
    },
    core::slice,
    std::iter::zip,
};

register_hash!(Blake3::new());

// Static assertions
const _: () = assert!(
    OUT_LEN == 32,
    "Blake3 compression output does not equal hash size."
);
const _: () = assert!(
    BLOCK_LEN == 2 * 32,
    "Blake3 compression input does not equal a pair of hashes."
);
const _: () = assert!(
    CHUNK_LEN == 16 * BLOCK_LEN,
    "Blake3 chunk len is not 16 blocks."
);

/// Default Blake3 initialization vector. Copied here because it is not publicly
/// exported.
const BLAKE3_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Flags for a single block message. Copied here because it is not publicly
/// exported.
const FLAGS_START: u8 = 1 << 0; // CHUNK_START
const FLAGS_END: u8 = 1 << 1; // CHUNK_END
const FLAGS: u8 = 1 << 3; // ROOT

pub struct Blake3 {
    platform:       Platform,
    implementation: String,
}

impl Blake3 {
    pub fn new() -> Self {
        let platform = Platform::detect();
        Self {
            platform,
            implementation: format!("{:?}", platform),
        }
    }

    fn hash_many_const<const N: usize>(&self, inputs: &[u8], output: &mut [u8]) {
        // Cast the input to a slice of N-sized arrays.
        let inputs = as_chunks_exact::<u8, N>(inputs);

        // Process up to MAX_SIMD_DEGREE messages in parallel.
        for (inputs, out) in zip(
            inputs.chunks(MAX_SIMD_DEGREE),
            output.chunks_mut(OUT_LEN * MAX_SIMD_DEGREE),
        ) {
            // Construct an array of references to input messages.
            let inputs = inputs
                .iter()
                .collect::<ArrayVec<&[u8; N], MAX_SIMD_DEGREE>>();

            // Hash the messages in parallel.
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
}

impl SmolHasher for Blake3 {
    fn hash_fn(&self) -> HashFn {
        HashFn::Blake3
    }

    fn implementation(&self) -> &str {
        &self.implementation
    }

    fn hash(&self, inputs: &[u8], output: &mut [u8]) {
        let size = 64;
        assert!(
            size % BLOCK_LEN == 0,
            "Message size must be a multiple of the block length."
        );
        assert!(
            size <= CHUNK_LEN,
            "Message size must not exceed a single chunk."
        );
        assert!(
            inputs.len() % size == 0,
            "Input size must be a multiple of the message size."
        );
        assert!(
            inputs.len() % 32 == 0,
            "Output size must be a multiple of the hash size."
        );
        assert_eq!(
            output.len() / 32,
            inputs.len() / size,
            "Output size mismatch."
        );
        let blocks = size / BLOCK_LEN;

        // Undo the monomorphization that Blake3 has in their API.
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

/// Cast a mutable slice into chunks of size N.
///
/// TODO: Replace with `slice::as_chunks` when stable.
pub fn as_chunks_exact<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    assert!(N != 0, "chunk size must be non-zero");
    assert_eq!(
        slice.len() % N,
        0,
        "slice length must be a multiple of chunk size"
    );
    // SAFETY: Caller must guarantee that `N` is nonzero and exactly divides the
    // slice length
    let new_len = slice.len() / N;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    unsafe { slice::from_raw_parts(slice.as_ptr().cast(), new_len) }
}
