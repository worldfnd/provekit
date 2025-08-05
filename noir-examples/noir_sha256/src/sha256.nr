use std::hash::sha256_compression;
use std::runtime::is_unconstrained;

use constants::{
    BLOCK_BYTE_PTR, BLOCK_SIZE, HASH, INITIAL_STATE, INT_BLOCK, INT_BLOCK_SIZE, INT_SIZE,
    INT_SIZE_PTR, MSG_BLOCK, MSG_SIZE_PTR, STATE, TWO_POW_16, TWO_POW_24, TWO_POW_32, TWO_POW_8,
};

pub(crate) mod constants;
mod tests;

// Implementation of SHA-256 mapping a byte array of variable length to
// 32 bytes.

// Deprecated in favour of `sha256_var`
// docs:start:sha256
pub fn sha256<let N: u32>(input: [u8; N]) -> HASH
// docs:end:sha256
{
    digest(input)
}

// SHA-256 hash function
#[no_predicates]
pub fn digest<let N: u32>(msg: [u8; N]) -> HASH {
    sha256_var(msg, N as u64)
}

// Variable size SHA-256 hash
pub fn sha256_var<let N: u32>(msg: [u8; N], message_size: u64) -> HASH {
    let message_size = message_size as u32;
    assert(message_size <= N);

    if std::runtime::is_unconstrained() {
        // Safety: SHA256 is running as an unconstrained function.
        unsafe {
            __sha256_var(msg, message_size)
        }
    } else {
        let mut msg_block: MSG_BLOCK = [0; INT_BLOCK_SIZE];
        // Intermediate hash, starting with the canonical initial value
        let mut h: STATE = INITIAL_STATE;
        // Pointer into msg_block on a 64 byte scale
        let mut msg_byte_ptr = 0;
        let num_blocks = N / BLOCK_SIZE;
        for i in 0..num_blocks {
            let msg_start = BLOCK_SIZE * i;
            let (new_msg_block, new_msg_byte_ptr) =
                unsafe { build_msg_block(msg, message_size, msg_start) };

            if msg_start < message_size {
                msg_block = new_msg_block;
            }

            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }

            // If the block is filled, compress it.
            // An un-filled block is handled after this loop.
            if (msg_start < message_size) & (msg_byte_ptr == BLOCK_SIZE) {
                h = sha256_compression(msg_block, h);
            }
        }

        let modulo = N % BLOCK_SIZE;
        // Handle setup of the final msg block.
        // This case is only hit if the msg is less than the block size,
        // or our message cannot be evenly split into blocks.
        if modulo != 0 {
            let msg_start = BLOCK_SIZE * num_blocks;
            let (new_msg_block, new_msg_byte_ptr) =
                unsafe { build_msg_block(msg, message_size, msg_start) };

            if msg_start < message_size {
                msg_block = new_msg_block;
            }

            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
                verify_msg_block_padding(msg_block, msg_byte_ptr);
            }
        }

        // If we had modulo == 0 then it means the last block was full,
        // and we can reset the pointer to zero to overwrite it.
        if msg_byte_ptr == BLOCK_SIZE {
            msg_byte_ptr = 0;
        }

        // Pad the rest such that we have a [u32; 2] block at the end representing the length
        // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
        // Here we rely on the fact that everything beyond the available input is set to 0.
        let index = msg_byte_ptr / INT_SIZE;
        msg_block[index] = set_item_byte_then_zeros(msg_block[index], msg_byte_ptr, 1 << 7);

        msg_byte_ptr = msg_byte_ptr + 1;
        let last_block = msg_block;

        // If we don't have room to write the size, compress the block and reset it.
        if msg_byte_ptr > MSG_SIZE_PTR {
            h = sha256_compression(msg_block, h);
            // `attach_len_to_msg_block` will zero out everything after the `msg_byte_ptr`.
            msg_byte_ptr = 0;
        }

        msg_block = unsafe { attach_len_to_msg_block(msg_block, msg_byte_ptr, message_size) };

        verify_msg_len(msg_block, last_block, msg_byte_ptr, message_size);

        hash_final_block(msg_block, h)
    }
}

// Variable size SHA-256 hash
unconstrained fn __sha256_var<let N: u32>(msg: [u8; N], message_size: u32) -> HASH {
    let num_full_blocks = message_size / BLOCK_SIZE;
    // Intermediate hash, starting with the canonical initial value
    let mut h: STATE = INITIAL_STATE;
    // Pointer into msg_block on a 64 byte scale
    for i in 0..num_full_blocks {
        let (msg_block, _) = build_msg_block(msg, message_size, BLOCK_SIZE * i);
        h = sha256_compression(msg_block, h);
    }

    // Handle setup of the final msg block.
    // This case is only hit if the msg is less than the block size,
    // or our message cannot be evenly split into blocks.
    let modulo = message_size % BLOCK_SIZE;
    let (mut msg_block, mut msg_byte_ptr): (INT_BLOCK, u32) = if modulo != 0 {
        let msg_start = BLOCK_SIZE * num_full_blocks;
        let (new_msg_block, new_msg_byte_ptr) = build_msg_block(msg, message_size, msg_start);
        (new_msg_block, new_msg_byte_ptr)
    } else {
        // If we had modulo == 0 then it means the last block was full,
        // and we can reset the pointer to zero to overwrite it.
        ([0; INT_BLOCK_SIZE], 0)
    };

    // Pad the rest such that we have a [u32; 2] block at the end representing the length
    // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
    // Here we rely on the fact that everything beyond the available input is set to 0.
    let index = msg_byte_ptr / INT_SIZE;
    msg_block[index] = set_item_byte_then_zeros(msg_block[index], msg_byte_ptr, 1 << 7);

    // If we don't have room to write the size, compress the block and reset it.
    let (h, mut msg_byte_ptr): (STATE, u32) = if msg_byte_ptr >= MSG_SIZE_PTR {
        // `attach_len_to_msg_block` will zero out everything after the `msg_byte_ptr`.
        (sha256_compression(msg_block, h), 0)
    } else {
        (h, msg_byte_ptr + 1)
    };
    msg_block = attach_len_to_msg_block(msg_block, msg_byte_ptr, message_size);

    hash_final_block(msg_block, h)
}

// Take `BLOCK_SIZE` number of bytes from `msg` starting at `msg_start`.
// Returns the block and the length that has been copied rather than padded with zeros.
unconstrained fn build_msg_block<let N: u32>(
    msg: [u8; N],
    message_size: u32,
    msg_start: u32,
) -> (MSG_BLOCK, BLOCK_BYTE_PTR) {
    let mut msg_block: MSG_BLOCK = [0; INT_BLOCK_SIZE];

    // We insert `BLOCK_SIZE` bytes (or up to the end of the message)
    let block_input = if message_size < msg_start {
        // This function is sometimes called with `msg_start` past the end of the message.
        // In this case we return an empty block and zero pointer to signal that the result should be ignored.
        0
    } else if message_size < msg_start + BLOCK_SIZE {
        message_size - msg_start
    } else {
        BLOCK_SIZE
    };

    // Figure out the number of items in the int array that we have to pack.
    // e.g. if the input is [0,1,2,3,4,5] then we need to pack it as 2 items: [0123, 4500]
    let int_input = (block_input + INT_SIZE - 1) / INT_SIZE;

    for i in 0..int_input {
        let mut msg_item: u32 = 0;
        // Always construct the integer as 4 bytes, even if it means going beyond the input.
        for j in 0..INT_SIZE {
            let k = i * INT_SIZE + j;
            let msg_byte = if k < block_input {
                msg[msg_start + k]
            } else {
                0
            };
            msg_item = lshift8(msg_item, 1) + msg_byte as u32;
        }
        msg_block[i] = msg_item;
    }

    // Returning the index as if it was a 64 byte array.
    // We have to project it down to 16 items and bit shifting to get a byte back if we need it.
    (msg_block, block_input)
}

// Verify the block we are compressing was appropriately constructed by `build_msg_block`
// and matches the input data. Returns the index of the first unset item.
// If `message_size` is less than `msg_start` then this is called with the old non-empty block;
// in that case we can skip verification, ie. no need to check that everything is zero.
fn verify_msg_block<let N: u32>(
    msg: [u8; N],
    message_size: u32,
    msg_block: MSG_BLOCK,
    msg_start: u32,
) -> BLOCK_BYTE_PTR {
    let mut msg_byte_ptr = 0;
    let mut msg_end = msg_start + BLOCK_SIZE;
    if msg_end > N {
        msg_end = N;
    }
    // We might have to go beyond the input to pad the fields.
    if msg_end % INT_SIZE != 0 {
        msg_end = msg_end + INT_SIZE - msg_end % INT_SIZE;
    }

    // Reconstructed packed item.
    let mut msg_item: u32 = 0;

    // Inclusive at the end so that we can compare the last item.
    let mut i: u32 = 0;
    for k in msg_start..=msg_end {
        if k % INT_SIZE == 0 {
            // If we consumed some input we can compare against the block.
            if (msg_start < message_size) & (k > msg_start) {
                assert_eq(msg_block[i], msg_item as u32);
                i = i + 1;
                msg_item = 0;
            }
        }
        // Shift the accumulator
        msg_item = lshift8(msg_item, 1);
        // If we have input to consume, add it at the rightmost position.
        if k < message_size & k < msg_end {
            msg_item = msg_item + msg[k] as u32;
            msg_byte_ptr = msg_byte_ptr + 1;
        }
    }

    msg_byte_ptr
}

// Verify the block we are compressing was appropriately padded with zeros by `build_msg_block`.
// This is only relevant for the last, potentially partially filled block.
fn verify_msg_block_padding(msg_block: MSG_BLOCK, msg_byte_ptr: BLOCK_BYTE_PTR) {
    // Check all the way to the end of the block.
    verify_msg_block_zeros(msg_block, msg_byte_ptr, INT_BLOCK_SIZE);
}

// Verify that a region of ints in the message block are (partially) zeroed,
// up to an (exclusive) maximum which can either be the end of the block
// or just where the size is to be written.
fn verify_msg_block_zeros(
    msg_block: MSG_BLOCK,
    mut msg_byte_ptr: BLOCK_BYTE_PTR,
    max_int_byte_ptr: u32,
) {
    // This variable is used to get around the compiler under-constrained check giving a warning.
    // We want to check against a constant zero, but if it does not come from the circuit inputs
    // or return values the compiler check will issue a warning.
    let zero = msg_block[0] - msg_block[0];

    // First integer which is supposed to be (partially) zero.
    let mut int_byte_ptr = msg_byte_ptr / INT_SIZE;

    // Check partial zeros.
    let modulo = msg_byte_ptr % INT_SIZE;
    if modulo != 0 {
        let zeros = INT_SIZE - modulo;
        let mask = if zeros == 3 {
            TWO_POW_24
        } else if zeros == 2 {
            TWO_POW_16
        } else {
            TWO_POW_8
        };
        assert_eq(msg_block[int_byte_ptr] % mask, zero);
        int_byte_ptr = int_byte_ptr + 1;
    }

    // Check the rest of the items.
    for i in 0..max_int_byte_ptr {
        if i >= int_byte_ptr {
            assert_eq(msg_block[i], zero);
        }
    }
}

// Verify that up to the byte pointer the two blocks are equal.
// At the byte pointer the new block can be partially zeroed.
fn verify_msg_block_equals_last(
    msg_block: MSG_BLOCK,
    last_block: MSG_BLOCK,
    mut msg_byte_ptr: BLOCK_BYTE_PTR,
) {
    // msg_byte_ptr is the position at which they are no longer have to be the same.
    // First integer which is supposed to be (partially) zero contains that pointer.
    let mut int_byte_ptr = msg_byte_ptr / INT_SIZE;

    // Check partial zeros.
    let modulo = msg_byte_ptr % INT_SIZE;
    if modulo != 0 {
        // Reconstruct the partially zero item from the last block.
        let last_field = last_block[int_byte_ptr];
        let mut msg_item: u32 = 0;
        // Reset to where they are still equal.
        msg_byte_ptr = msg_byte_ptr - modulo;
        for i in 0..INT_SIZE {
            msg_item = lshift8(msg_item, 1);
            if i < modulo {
                msg_item = msg_item + get_item_byte(last_field, msg_byte_ptr) as u32;
                msg_byte_ptr = msg_byte_ptr + 1;
            }
        }
        assert_eq(msg_block[int_byte_ptr], msg_item);
    }

    for i in 0..INT_SIZE_PTR {
        if i < int_byte_ptr {
            assert_eq(msg_block[i], last_block[i]);
        }
    }
}

// Set the rightmost `zeros` number of bytes to 0.
#[inline_always]
fn set_item_zeros(item: u32, zeros: u8) -> u32 {
    lshift8(rshift8(item, zeros), zeros)
}

// Replace one byte in the item with a value, and set everything after it to zero.
fn set_item_byte_then_zeros(msg_item: u32, msg_byte_ptr: BLOCK_BYTE_PTR, msg_byte: u8) -> u32 {
    let zeros = INT_SIZE - msg_byte_ptr % INT_SIZE;
    let zeroed_item = set_item_zeros(msg_item, zeros as u8);
    let new_item = byte_into_item(msg_byte, msg_byte_ptr);
    zeroed_item + new_item
}

// Get a byte of a message item according to its overall position in the `BLOCK_SIZE` space.
fn get_item_byte(mut msg_item: u32, msg_byte_ptr: BLOCK_BYTE_PTR) -> u8 {
    // How many times do we have to shift to the right to get to the position we want?
    let max_shifts = INT_SIZE - 1;
    let shifts = max_shifts - msg_byte_ptr % INT_SIZE;
    msg_item = rshift8(msg_item, shifts as u8);
    // At this point the byte we want is in the rightmost position.
    msg_item as u8
}

// Project a byte into a position in a field based on the overall block pointer.
// For example putting 1 into pointer 5 would be 100, because overall we would
// have [____, 0100] with indexes [0123,4567].
#[inline_always]
fn byte_into_item(msg_byte: u8, msg_byte_ptr: BLOCK_BYTE_PTR) -> u32 {
    let mut msg_item = msg_byte as u32;
    // How many times do we have to shift to the left to get to the position we want?
    let max_shifts = INT_SIZE - 1;
    let shifts = max_shifts - msg_byte_ptr % INT_SIZE;
    lshift8(msg_item, shifts as u8)
}

// Construct a field out of 4 bytes.
#[inline_always]
fn make_item(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    let mut item = b0 as u32;
    item = lshift8(item, 1) + b1 as u32;
    item = lshift8(item, 1) + b2 as u32;
    item = lshift8(item, 1) + b3 as u32;
    item
}

// Shift by 8 bits to the left between 0 and 4 times.
// Checks `is_unconstrained()` to just use a bitshift if we're running in an unconstrained context,
// otherwise multiplies by 256.
#[inline_always]
fn lshift8(item: u32, shifts: u8) -> u32 {
    if is_unconstrained() {
        // Brillig wouldn't shift 0<<4 without overflow.
        if shifts >= 4 {
            0
        } else {
            item << (8 * shifts)
        }
    } else {
        // We can do a for loop up to INT_SIZE or an if-else.
        if shifts == 0 {
            item
        } else if shifts == 1 {
            item * TWO_POW_8
        } else if shifts == 2 {
            item * TWO_POW_16
        } else if shifts == 3 {
            item * TWO_POW_24
        } else {
            // Doesn't make sense, but it's most likely called on 0 anyway.
            0
        }
    }
}

// Shift by 8 bits to the right between 0 and 4 times.
// Checks `is_unconstrained()` to just use a bitshift if we're running in an unconstrained context,
// otherwise divides by 256.
#[inline_always]
fn rshift8(item: u32, shifts: u8) -> u32 {
    if is_unconstrained() {
        item >> (8 * shifts)
    } else {
        // Division wouldn't work on `Field`.
        if shifts == 0 {
            item
        } else if shifts == 1 {
            item / TWO_POW_8
        } else if shifts == 2 {
            item / TWO_POW_16
        } else if shifts == 3 {
            item / TWO_POW_24
        } else {
            0
        }
    }
}

// Convert a u64 to a byte array in big endian order.
fn u64_to_be_bytes(x: u64) -> [u8; 8] {
    [
        ((x >> 56) & 0xFF) as u8,
        ((x >> 48) & 0xFF) as u8,
        ((x >> 40) & 0xFF) as u8,
        ((x >> 32) & 0xFF) as u8,
        ((x >> 24) & 0xFF) as u8,
        ((x >> 16) & 0xFF) as u8,
        ((x >> 8) & 0xFF) as u8,
        (x & 0xFF) as u8,
    ]
}

// Convert a u32 to a byte array in big endian order.
fn u32_to_be_bytes(x: u32) -> [u8; 4] {
    [((x >> 24) & 0xFF) as u8, ((x >> 16) & 0xFF) as u8, ((x >> 8) & 0xFF) as u8, (x & 0xFF) as u8]
}

// Zero out all bytes between the end of the message and where the length is appended,
// then write the length into the last 8 bytes of the block.
unconstrained fn attach_len_to_msg_block(
    mut msg_block: MSG_BLOCK,
    mut msg_byte_ptr: BLOCK_BYTE_PTR,
    message_size: u32,
) -> MSG_BLOCK {
    // We assume that `msg_byte_ptr` is less than 57 because if not then it is reset to zero before calling this function.
    // In any case, fill blocks up with zeros until the last 64 bits (i.e. until msg_byte_ptr = 56).
    // There can be one item which has to be partially zeroed.
    let modulo = msg_byte_ptr % INT_SIZE;
    if modulo != 0 {
        // Index of the block in which we find the item we need to partially zero.
        let i = msg_byte_ptr / INT_SIZE;
        let zeros = INT_SIZE - modulo;
        msg_block[i] = set_item_zeros(msg_block[i], zeros as u8);
        msg_byte_ptr = msg_byte_ptr + zeros;
    }

    // The rest can be zeroed without bit shifting anything.
    for i in (msg_byte_ptr / INT_SIZE)..INT_SIZE_PTR {
        msg_block[i] = 0;
    }

    // Set the last two 4 byte ints as the first/second half of the 8 bytes of the length.
    let len = 8 * message_size;
    let len_bytes: [u8; 8] = u64_to_be_bytes(len as u64);
    msg_block[INT_SIZE_PTR] = (len_bytes[0] as u32) << 24
        | (len_bytes[1] as u32) << 16
        | (len_bytes[2] as u32) << 8
        | (len_bytes[3] as u32);

    msg_block[INT_SIZE_PTR + 1] = (len_bytes[4] as u32) << 24
        | (len_bytes[5] as u32) << 16
        | (len_bytes[6] as u32) << 8
        | (len_bytes[7] as u32);

    msg_block
}

// Verify that the message length was correctly written by `attach_len_to_msg_block`,
// and that everything between the byte pointer and the size pointer was zeroed,
// and that everything before the byte pointer was untouched.
fn verify_msg_len(
    msg_block: MSG_BLOCK,
    last_block: MSG_BLOCK,
    msg_byte_ptr: BLOCK_BYTE_PTR,
    message_size: u32,
) {
    // Check zeros up to the size pointer.
    verify_msg_block_zeros(msg_block, msg_byte_ptr, INT_SIZE_PTR);

    // Check that up to the pointer we match the last block.
    verify_msg_block_equals_last(msg_block, last_block, msg_byte_ptr);

    // We verify the message length was inserted correctly by reversing the byte decomposition.
    let mut reconstructed_len: u64 = 0;
    for i in INT_SIZE_PTR..INT_BLOCK_SIZE {
        reconstructed_len = reconstructed_len * TWO_POW_32;
        reconstructed_len = reconstructed_len + msg_block[i] as u64;
    }
    let len = 8 * message_size as u64;
    assert_eq(reconstructed_len, len);
}

// Perform the final compression, then transform the `STATE` into `HASH`.
fn hash_final_block(msg_block: MSG_BLOCK, mut state: STATE) -> HASH {
    let mut out_h: HASH = [0; 32]; // Digest as sequence of bytes
    // Hash final padded block
    state = sha256_compression(msg_block, state);

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 4] = u32_to_be_bytes(state[j]);
        for k in 0..4 {
            out_h[4 * j + k] = h_bytes[k];
        }
    }

    out_h
}

mod equivalence_test {

    #[test]
    fn test_implementations_agree(msg: [u8; 100], message_size: u64) {
        let message_size = message_size % 100;
        // Safety: test function
        let unconstrained_sha = unsafe { super::__sha256_var(msg, message_size as u32) };
        let sha = super::sha256_var(msg, message_size);
        assert_eq(sha, unconstrained_sha);
    }
}
