use crate::{
    sha256_start, sha256_continue, sha256_finalize,
    commit_to_sha256_state, 
    state_to_hash, build_msg_block,
    SHA256State, SHA256_IV,
};
use sha256::sha256_var;

// sha256_start should fail with non-64-multiple size
#[test(should_fail_with = "Message size must be a multiple of 64 bytes")]
fn test_sha256_start_invalid_size() {
    let msg: [u8; 63] = [0; 63]; // Not a multiple of 64
    let _ = sha256_start(msg);
}

//  sha256_continue with zero bytes should preserve state
#[test]
fn test_sha256_continue_zero_bytes() {
    let chunk1: [u8; 64] = [0x61; 64];
    let state1 = sha256_start(chunk1);

    let chunk2: [u8; 64] = [0; 64];
    let state2 = sha256_continue(state1, chunk2, 0);

    assert(state2 == state1);
}

// sha256_finalize basic functionality
#[test]
fn test_sha256_finalize_basic() {
    let chunk: [u8; 64] = [0x61; 64];
    let state = sha256_start(chunk);

    let final_bytes: [u8; 10] = [0x62; 10];
    let hash = sha256_finalize(state, final_bytes, 10, 74);

    assert(hash.len() == 32);
}

// compare partial SHA256 with std::hash::sha256
// short message (less than 64 bytes)
#[test]
fn test_partial_sha256_matches_std_short() {
    let msg: [u8; 50] = [0x61; 50];

    // Using standard sha256
    let std_hash = sha256_var(msg, msg.len() as u64);

    // Using partial sha256: no initial blocks, just finalize
    let state = SHA256_IV;
    let partial_hash = sha256_finalize(state, msg, 50, 50);

    assert(partial_hash == std_hash);
}

// 64 byte message
#[test]
fn test_partial_sha256_matches_std_one_block() {
    let msg: [u8; 64] = [0x61; 64];

    let std_hash = sha256_var(msg, msg.len() as u64);

    // Process as one block + empty finalize
    let state = sha256_start(msg);
    let empty: [u8; 0] = [];
    let partial_hash = sha256_finalize(state, empty, 0, 64);

    assert(partial_hash == std_hash);
}

// multi-block message
#[test]
fn test_partial_sha256_matches_std_multi_block() {
    // 150 bytes: 128 bytes (2 blocks) + 22 bytes final
    let msg: [u8; 150] = [0x61; 150];

    let std_hash = sha256_var(msg, msg.len() as u64);

    // Split processing
    let mut chunk1: [u8; 128] = [0; 128];
    for i in 0..128 {
        chunk1[i] = msg[i];
    }

    let state = sha256_start(chunk1);

    let mut final_chunk: [u8; 22] = [0; 22];
    for i in 0..22 {
        final_chunk[i] = msg[128 + i];
    }

    let partial_hash = sha256_finalize(state, final_chunk, 22, 150);

    assert(partial_hash == std_hash);
}

// build_msg_block helper function
#[test]
fn test_build_msg_block() {
    let mut msg: [u8; 64] = [0; 64];
    msg[0] = 0x61;
    msg[1] = 0x62;
    msg[2] = 0x63;
    msg[3] = 0x64;

    let block = build_msg_block(msg, 0, 64);

    // First word should be 0x61626364 (big-endian)
    assert(block[0] == 0x61626364);
}

// state_to_hash conversion
#[test]
fn test_state_to_hash() {
    let state: SHA256State = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let hash = state_to_hash(state);

    // First 4 bytes should be 0x6a, 0x09, 0xe6, 0x67
    assert(hash[0] == 0x6a);
    assert(hash[1] == 0x09);
    assert(hash[2] == 0xe6);
    assert(hash[3] == 0x67);
}

// commit_to_sha256_state
#[test]
fn test_commit_to_sha256_state() {
    let salt: Field = 12345;
    let state = SHA256_IV;
    let processed_bytes: u32 = 64;

    let comm1 = commit_to_sha256_state(salt, state, processed_bytes);
    let comm2 = commit_to_sha256_state(salt, state, processed_bytes);

    assert(comm1 == comm2);
}

// Integration test based on test_partial_sha256_verify circuit
#[test]
fn test_integration_640_640_split() {
    // Simulate the test_partial_sha256_verify scenario
    let tbs_cert_len: u32 = 1250; // Actual length

    // Create a test message
    let tbs_certificate: [u8; 1300] = [0x61; 1300];

    // Extract chunk1 (first 640 bytes)
    let mut chunk1: [u8; 640] = [0; 640];
    for i in 0..640 {
        chunk1[i] = tbs_certificate[i];
    }

    // Process chunk1
    let state1 = sha256_start(chunk1);

    // Calculate remaining
    let remaining_size = tbs_cert_len - 640;
    let num_full_blocks = remaining_size / 64;
    let full_block_bytes = num_full_blocks * 64;
    let final_partial_bytes = remaining_size - full_block_bytes;

    // Extract chunk2 (640 more bytes)
    let mut chunk2: [u8; 640] = [0; 640];
    for i in 0..640 {
        chunk2[i] = tbs_certificate[640 + i];
    }

    // Continue with full blocks
    let state2 = sha256_continue(state1, chunk2, full_block_bytes);

    // Extract final block
    let mut final_block: [u8; 64] = [0; 64];
    for i in 0..64 {
        if i < final_partial_bytes {
            final_block[i] = chunk2[full_block_bytes + i];
        }
    }

    // Finalize
    let partial_hash = sha256_finalize(state2, final_block, final_partial_bytes, tbs_cert_len);

    // Compare with standard SHA256
    let mut msg_actual: [u8; 1250] = [0; 1250];
    for i in 0..1250 {
        msg_actual[i] = tbs_certificate[i];
    }
    let std_hash = sha256_var(msg_actual, msg_actual.len() as u64);

    assert(partial_hash == std_hash);
}
