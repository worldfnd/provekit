// A message block is up to 64 bytes taken from the input.
pub(crate) global BLOCK_SIZE: u32 = 64;

// The first index in the block where the 8 byte message size will be written.
pub(crate) global MSG_SIZE_PTR: u32 = 56;

// Size of the message block when packed as 4-byte integer array.
pub(crate) global INT_BLOCK_SIZE: u32 = 16;

// A `u32` integer consists of 4 bytes.
pub(crate) global INT_SIZE: u32 = 4;

// Index of the integer in the `INT_BLOCK` where the length is written.
pub(crate) global INT_SIZE_PTR: u32 = MSG_SIZE_PTR / INT_SIZE;

// Magic numbers for bit shifting.
// Works with actual bit shifting as well as the compiler turns them into * and /
// but circuit execution appears to be 10% faster this way.
pub(crate) global TWO_POW_8: u32 = 256;
pub(crate) global TWO_POW_16: u32 = TWO_POW_8 * 256;
pub(crate) global TWO_POW_24: u32 = TWO_POW_16 * 256;
pub(crate) global TWO_POW_32: u64 = TWO_POW_24 as u64 * 256;

// Index of a byte in a 64 byte block; ie. 0..=63
pub(crate) type BLOCK_BYTE_PTR = u32;

// The foreign function to compress blocks works on 16 pieces of 4-byte integers, instead of 64 bytes.
pub(crate) type INT_BLOCK = [u32; INT_BLOCK_SIZE];

// A message block is a slice of the original message of a fixed size,
// potentially padded with zeros, with neighbouring 4 bytes packed into integers.
pub(crate) type MSG_BLOCK = INT_BLOCK;

// The hash is 32 bytes.
pub(crate) type HASH = [u8; 32];

// The state accumulates the blocks.
// Its overall size is the same as the `HASH`.
pub(crate) type STATE = [u32; 8];

pub(crate) global INITIAL_STATE: STATE =
    [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
