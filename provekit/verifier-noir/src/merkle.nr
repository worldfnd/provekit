// SHA256 Merkle Tree Verification
//
// Verifies Merkle inclusion proofs for WHIR commitment queries.
//
// Reference: recursive-verifier/app/circuit/whir_utilities.go (verifyMerkleTreeProofs)
//
// Leaf hashing: hash the FOLD_SIZE field elements together.
// Path verification: walk up using sibling hashes, select left/right by index bits.

use crate::types::{
    SHA256_INIT,
    field_to_bytes_le, u64_to_be_bytes,
};
use std::hash::sha256_compression;

// --- SHA256 helpers for Merkle ---

// Convert 64 bytes to 16 big-endian u32 words.
fn bytes_to_u32x16(bytes: [u8; 64]) -> [u32; 16] {
    let mut words: [u32; 16] = [0; 16];
    for i in 0..16 {
        let off = i * 4;
        words[i] = ((bytes[off] as u32) << 24)
            | ((bytes[off + 1] as u32) << 16)
            | ((bytes[off + 2] as u32) << 8)
            | (bytes[off + 3] as u32);
    }
    words
}

// Convert SHA256 state (8 x u32) to 32 bytes big-endian.
fn state_to_bytes(state: [u32; 8]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..8 {
        out[4 * i]     = ((state[i] >> 24) & 0xFF) as u8;
        out[4 * i + 1] = ((state[i] >> 16) & 0xFF) as u8;
        out[4 * i + 2] = ((state[i] >> 8) & 0xFF) as u8;
        out[4 * i + 3] = (state[i] & 0xFF) as u8;
    }
    out
}

// SHA256 of exactly 64 bytes (one block, with padding).
// Used for hashing two 32-byte siblings together.
fn sha256_two_blocks(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    // Block 1: the 64 data bytes
    let mut block1_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        block1_bytes[i] = left[i];
        block1_bytes[32 + i] = right[i];
    }
    let block1 = bytes_to_u32x16(block1_bytes);
    let state1 = sha256_compression(block1, SHA256_INIT);

    // Block 2: padding
    // 0x80 at byte 0, then zeros, length = 512 bits = 0x0200 at last 8 bytes
    let mut block2_bytes: [u8; 64] = [0; 64];
    block2_bytes[0] = 0x80;
    block2_bytes[62] = 0x02; // 512 >> 8
    block2_bytes[63] = 0x00; // 512 & 0xFF
    let block2 = bytes_to_u32x16(block2_bytes);
    let state2 = sha256_compression(block2, state1);

    state_to_bytes(state2)
}

// SHA256 of a variable number of 32-byte field element encodings.
// Used to hash leaf values.
fn sha256_field_elements<let N: u32>(fields: [Field; N]) -> [u8; 32] {
    let total_bytes: u32 = N * 32;

    // Process 64-byte blocks
    let mut state = SHA256_INIT;
    let mut byte_buf: [u8; 64] = [0; 64];
    let mut buf_pos: u32 = 0;

    for i in 0..N {
        let f_bytes = field_to_bytes_le(fields[i]);
        for j in 0..32 {
            byte_buf[buf_pos] = f_bytes[j];
            buf_pos += 1;
            if buf_pos == 64 {
                let block = bytes_to_u32x16(byte_buf);
                state = sha256_compression(block, state);
                byte_buf = [0; 64];
                buf_pos = 0;
            }
        }
    }

    // Padding
    let total_bits: u64 = (total_bytes as u64) * 8;
    byte_buf[buf_pos] = 0x80;
    buf_pos += 1;

    // Check if we need an extra block for padding
    if buf_pos > 56 {
        // Fill rest with zeros and process
        let block = bytes_to_u32x16(byte_buf);
        state = sha256_compression(block, state);
        byte_buf = [0; 64];
    }

    // Write length at end
    let len_bytes = u64_to_be_bytes(total_bits);
    for i in 0..8 {
        byte_buf[56 + i] = len_bytes[i];
    }
    let block = bytes_to_u32x16(byte_buf);
    state = sha256_compression(block, state);

    state_to_bytes(state)
}

// --- Merkle Proof Verification ---

// Verify a single Merkle inclusion proof.
//
// - leaf_values: the FOLD_SIZE field elements at this leaf
// - siblings: sibling hashes along the path (bottom to top)
// - index: leaf index in the tree (used for left/right selection)
// - root: expected Merkle root hash
pub fn verify_merkle_proof<let LEAF_SIZE: u32, let HEIGHT: u32>(
    leaf_values: [Field; LEAF_SIZE],
    siblings: [[u8; 32]; HEIGHT],
    index: u32,
    root: [u8; 32],
) {
    // Step 1: Hash the leaf values
    let mut current = sha256_field_elements(leaf_values);

    // Step 2: Walk up the tree
    let mut idx = index;
    for i in 0..HEIGHT {
        let sibling = siblings[i];
        let is_right = idx & 1;
        idx = idx >> 1;

        if is_right == 1 {
            // current is right child
            current = sha256_two_blocks(sibling, current);
        } else {
            // current is left child
            current = sha256_two_blocks(current, sibling);
        }
    }

    // Step 3: Assert root match
    assert(current == root, "Merkle proof verification failed: root mismatch");
}
