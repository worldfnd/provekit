// Partial SHA256 implementation for splitting computation across circuits
// Based on RFC 6234, uses std::hash::sha256_compression for block processing

mod tests;

use poseidon::poseidon2::Poseidon2;
use std::hash::sha256_compression;

pub global BLOCK_SIZE: u32 = 64;
pub global SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
pub type SHA256State = [u32; 8];

fn build_msg_block<let N: u32>(msg: [u8; N], msg_start: u32, valid_bytes: u32) -> [u32; 16] {
    let mut block: [u32; 16] = [0; 16];
    for i in 0..16 {
        let byte_idx = msg_start + i * 4;
        let mut word: u32 = 0;
        for j in 0..4 {
            word = word << 8;
            let idx = byte_idx + j;
            if idx < msg_start + valid_bytes {
                word = word + msg[idx] as u32;
            }
        }
        block[i] = word;
    }
    block
}

fn state_to_hash(state: SHA256State) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    for i in 0..8 {
        let word = state[i];
        hash[i * 4] = ((word >> 24) & 0xff) as u8;
        hash[i * 4 + 1] = ((word >> 16) & 0xff) as u8;
        hash[i * 4 + 2] = ((word >> 8) & 0xff) as u8;
        hash[i * 4 + 3] = (word & 0xff) as u8;
    }
    hash
}

/// Process first N bytes (must be multiple of 64), returns intermediate SHA256 state
pub fn sha256_start<let N: u32>(msg: [u8; N]) -> SHA256State {
    assert(N % BLOCK_SIZE == 0, "Message size must be a multiple of 64 bytes");
    let num_blocks = N / BLOCK_SIZE;
    let mut state = SHA256_IV;

    for i in 0..num_blocks {
        let block = build_msg_block(msg, i * BLOCK_SIZE, BLOCK_SIZE);
        state = sha256_compression(block, state);
    }
    state
}

/// Continue processing from previous state (msg_size must be multiple of 64)
pub fn sha256_continue<let N: u32>(
    state: SHA256State,
    msg: [u8; N],
    msg_size: u32,
) -> SHA256State {
    assert(msg_size % BLOCK_SIZE == 0, "Message size must be a multiple of 64 bytes");
    assert(msg_size <= N, "Message size exceeds buffer size");

    let max_blocks = N / BLOCK_SIZE;
    let mut current_state = state;

    for i in 0..max_blocks {
        if (i * BLOCK_SIZE) < msg_size {
            let block = build_msg_block(msg, i * BLOCK_SIZE, BLOCK_SIZE);
            current_state = sha256_compression(block, current_state);
        }
    }
    current_state
}

/// Finalize SHA256 hash with RFC 6234 padding (0x80, zeros, 64-bit length)
/// msg_size must be < 64 (use sha256_continue for full blocks first)
pub fn sha256_finalize<let N: u32>(
    state: SHA256State,
    msg: [u8; N],
    msg_size: u32,
    total_msg_size: u32,
) -> [u8; 32] {
    assert(msg_size <= N, "Message size exceeds buffer size");
    assert(msg_size < BLOCK_SIZE, "Use sha256_continue for full blocks first");

    let mut current_state = state;
    let mut final_block: [u32; 16] = [0; 16];

    for i in 0..16 {
        let byte_idx = i * 4;
        let mut word: u32 = 0;
        for j in 0..4 {
            word = word << 8;
            let idx = byte_idx + j;
            if idx < msg_size {
                word = word + msg[idx] as u32;
            } else if idx == msg_size {
                word = word + 0x80;
            }
        }
        final_block[i] = word;
    }

    let total_bits = total_msg_size as u64 * 8;

    if msg_size + 9 > BLOCK_SIZE {
        current_state = sha256_compression(final_block, current_state);
        let mut length_block: [u32; 16] = [0; 16];
        length_block[14] = (total_bits >> 32) as u32;
        length_block[15] = (total_bits & 0xffffffff) as u32;
        current_state = sha256_compression(length_block, current_state);
    } else {
        final_block[14] = (total_bits >> 32) as u32;
        final_block[15] = (total_bits & 0xffffffff) as u32;
        current_state = sha256_compression(final_block, current_state);
    }

    state_to_hash(current_state)
}

/// Commits to SHA256 state: Poseidon2(salt, state[0..7], processed_bytes)
pub fn commit_to_sha256_state(
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
) -> Field {
    let mut hash_inputs: [Field; 10] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..8 {
        hash_inputs[1 + i] = state[i] as Field;
    }
    hash_inputs[9] = processed_bytes as Field;
    Poseidon2::hash(hash_inputs, 10)
}

pub fn verify_sha256_state_commitment(
    comm_in: Field,
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
) {
    let expected = commit_to_sha256_state(salt, state, processed_bytes);
    assert(comm_in == expected, "SHA256 state commitment verification failed");
}

/// Commits to SHA256 state + data: Poseidon2(salt, state[0..7], processed_bytes, data_commitment)
pub fn commit_to_sha256_state_and_data(
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
    data_commitment: Field,
) -> Field {
    let mut hash_inputs: [Field; 11] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..8 {
        hash_inputs[1 + i] = state[i] as Field;
    }
    hash_inputs[9] = processed_bytes as Field;
    hash_inputs[10] = data_commitment;
    Poseidon2::hash(hash_inputs, 11)
}

pub fn verify_sha256_state_and_data_commitment(
    comm_in: Field,
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
    data_commitment: Field,
) {
    let expected = commit_to_sha256_state_and_data(salt, state, processed_bytes, data_commitment);
    assert(comm_in == expected, "SHA256 state+data commitment verification failed");
}

pub fn commit_to_data_chunk<let N: u32>(salt: Field, data: [u8; N]) -> Field {
    let packed: [Field; (N + 30) / 31] = utils::pack_be_bytes_into_fields::<N, _, 31>(data);
    let mut hash_inputs: [Field; 1 + (N + 30) / 31] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..((N + 30) / 31) {
        hash_inputs[1 + i] = packed[i];
    }
    Poseidon2::hash(hash_inputs, 1 + (N + 30) / 31)
}