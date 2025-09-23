/// Note: This is the naive implementation of SHA-256's block compression
/// function, i.e. (state: [u32; 8], block: [u32; 16]) -> updated_state: [u32; 8].
///
/// This file has been optimized internally to use a standard loop-based approach
/// for the SHA-256 algorithm, while preserving the original function signatures.

use super::ryan_sha256_constants::{K32, MSG_BLOCK, STATE};
use std::static_assert;

// ------------------- ALL THE SHA STUFF -------------------

global SCHEDULE_SIZE: u32 = 64;
global BLOCK_WORDS: u32 = 16;

// Casting the 64-bit sum back to u32 automatically keeps the low 32 bits,
// which is equivalent to (a + b) mod 2^32.
fn add_u32(a: u32, b: u32) -> u32 {
    let sum = (a as u64) + (b as u64);
    sum as u32
}

fn add4_u32(a: u32, b: u32, c: u32, d: u32) -> u32 {
    let sum = (a as u64) + (b as u64) + (c as u64) + (d as u64);
    sum as u32
}

fn add5_u32(a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    let sum = (a as u64) + (b as u64) + (c as u64) + (d as u64) + (e as u64);
    sum as u32
}

// ------ Vec element-wise operations ------
fn vec_eltwise_add_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [add_u32(a[0], b[0]), add_u32(a[1], b[1]), add_u32(a[2], b[2]), add_u32(a[3], b[3])]
}

fn vec_shift_left_u32(a: [u32; 4], shift_offset: u8) -> [u32; 4] {
    [
        a[0] >> (shift_offset as u32),
        a[1] >> (shift_offset as u32),
        a[2] >> (shift_offset as u32),
        a[3] >> (shift_offset as u32),
    ]
}

fn vec_shift_right_u32(a: [u32; 4], shift_offset: u8) -> [u32; 4] {
    [
        a[0] << (shift_offset as u32),
        a[1] << (shift_offset as u32),
        a[2] << (shift_offset as u32),
        a[3] << (shift_offset as u32),
    ]
}

fn vec_eltwise_or_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]]
}

fn vec_eltwise_xor_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

// ------ Rotate left / rotate right functionality ------
/// Attempting to mimic the `rotate_left` and `rotate_right` functionality
/// using bit-shifts.
/// WARNING: CANNOT USE THIS IF ROTATION_AMT == 0
fn rotate_left_via_shift_u32(val: u32, rotation_amt: u8) -> u32 {
    let rotation_amt = rotation_amt % 32;
    static_assert(
        rotation_amt != 0,
        "Cannot use this function with `rotation_amt` = 0",
    );
    // 01234567|
    // 012|34567 -> 34567|012
    // We can do this with bit-masking and/or shifting
    let left_side_already_moved = val >> (32u32 - (rotation_amt as u32));
    let right_side_already_moved = val << (rotation_amt as u32);
    left_side_already_moved | right_side_already_moved
}

/// WARNING: CANNOT USE THIS IF ROTATION_AMT == 0
/// Also small note -- this is the elegant but probably inefficient way of doing it
fn rotate_right_via_shift_u32(val: u32, rotation_amt: u8) -> u32 {
    let rotation_amt = rotation_amt % 32;
    static_assert(
        rotation_amt != 0,
        "Cannot use this function with `rotation_amt` = 0",
    );
    rotate_left_via_shift_u32(val, 32 - rotation_amt)
}

// ------ `u32`-specific permutation operations ------
fn big_sigma0(a: u32) -> u32 {
    rotate_right_via_shift_u32(a, 2)
        ^ rotate_right_via_shift_u32(a, 13)
        ^ rotate_right_via_shift_u32(a, 22)
}

fn big_sigma1(a: u32) -> u32 {
    rotate_right_via_shift_u32(a, 6)
        ^ rotate_right_via_shift_u32(a, 11)
        ^ rotate_right_via_shift_u32(a, 25)
}

fn small_sigma0(x: u32) -> u32 {
    rotate_right_via_shift_u32(x, 7) ^ rotate_right_via_shift_u32(x, 18) ^ (x >> 3)
}

fn small_sigma1(x: u32) -> u32 {
    rotate_right_via_shift_u32(x, 17) ^ rotate_right_via_shift_u32(x, 19) ^ (x >> 10)
}

fn bool3ary_202(a: u32, b: u32, c: u32) -> u32 {
    c ^ (a & (b ^ c))
}

fn bool3ary_232(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

fn sha256load(v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    [v3[3], v2[0], v2[1], v2[2]]
}

// sigma 0 on vectors
fn sigma0x4(x: [u32; 4]) -> [u32; 4] {
    let t1 = vec_eltwise_or_u32(vec_shift_left_u32(x, 7), vec_shift_right_u32(x, 25));
    let t2 = vec_eltwise_or_u32(vec_shift_left_u32(x, 18), vec_shift_right_u32(x, 14));
    let t3 = vec_shift_left_u32(x, 3);
    vec_eltwise_xor_u32(vec_eltwise_xor_u32(t1, t2), t3)
}

fn sigma1(a: u32) -> u32 {
    rotate_right_via_shift_u32(a, 17) ^ rotate_right_via_shift_u32(a, 19) ^ (a >> 10)
}

fn sha256msg1(v0: [u32; 4], v1: [u32; 4]) -> [u32; 4] {
    vec_eltwise_add_u32(v0, sigma0x4(sha256load(v0, v1)))
}

fn sha256msg2(v4: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    // --- Manual unpacking ---
    // let [x3, x2, x1, x0] = v4;
    // let [w15, w14, _, _] = v3;
    let x3 = v4[0];
    let x2 = v4[1];
    let x1 = v4[2];
    let x0 = v4[3];
    let w15 = v3[0];
    let w14 = v3[1];

    let w16 = add_u32(x0, sigma1(w14));
    let w17 = add_u32(x1, sigma1(w15));
    let w18 = add_u32(x2, sigma1(w16));
    let w19 = add_u32(x3, sigma1(w17));

    [w19, w18, w17, w16]
}

fn schedule(v0: [u32; 4], v1: [u32; 4], v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    // --- Okay we do a `msg1` on the first half of the state ---
    let t1 = sha256msg1(v0, v1);
    // --- Then a `load` on the second half of the state ---
    let t2 = sha256load(v2, v3);
    // --- Then we add the two results together elt-wise ---
    let t3 = vec_eltwise_add_u32(t1, t2);
    // --- Then we do a `msg2` on the last part of the state and the result of the earlier add ---
    sha256msg2(t3, v3)
}

/// This is the main block compression function. Its internal logic has been optimized
/// to match the standard SHA-256 algorithm implementation.
pub fn ryan_sha256_digest_block_u32(state: STATE, block: MSG_BLOCK) -> [u32; 8] {
    // 1. Message Schedule Generation
    let mut schedule: [u32; SCHEDULE_SIZE] = [0; SCHEDULE_SIZE];
    for i in 0..BLOCK_WORDS {
        schedule[i] = block[i];
    }
    for t in BLOCK_WORDS..SCHEDULE_SIZE {
        let s0 = small_sigma0(schedule[t - 15]);
        let s1 = small_sigma1(schedule[t - 2]);
        schedule[t] = add4_u32(schedule[t - 16], s0, schedule[t - 7], s1);
    }

    // 2. Initialize working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // 3. Main Compression Loop (64 rounds)
    for t in 0..SCHEDULE_SIZE {
        let w = schedule[t];
        let k = K32[t];

        let sigma1_e = big_sigma1(e);
        let ch_efg = bool3ary_202(e, f, g);
        let temp1 = add5_u32(h, sigma1_e, ch_efg, k, w);

        let sigma0_a = big_sigma0(a);
        let maj_abc = bool3ary_232(a, b, c);
        let temp2 = add_u32(sigma0_a, maj_abc);

        h = g;
        g = f;
        f = e;
        e = add_u32(d, temp1);
        d = c;
        c = b;
        b = a;
        a = add_u32(temp1, temp2);
    }

    // 4. Add the compressed block to the initial state
    [
        add_u32(state[0], a),
        add_u32(state[1], b),
        add_u32(state[2], c),
        add_u32(state[3], d),
        add_u32(state[4], e),
        add_u32(state[5], f),
        add_u32(state[6], g),
        add_u32(state[7], h),
    ]
}

mod test {
    #[test]
    fn test_no_overflow() {
        let res = super::add_u32(1, 2);
        assert(res == 3);
    }

    #[test]
    fn test_overflow_exact() {
        let max = 0xFFFFFFFF;
        let res = super::add_u32(max, 1);
        assert(res == 0);
    }

    #[test]
    fn test_overflow_carry() {
        let max = 0xFFFFFFFF;
        let res = super::add_u32(max, 2);
        assert(res == 1);
    }

    #[test]
    fn test_large_sum() {
        let res = super::add_u32(4000000000, 4000000000);
        assert(res == 3705032704);
    }
}
