/// Note: This is the naive implementation of SHA-256's block compression
/// function, i.e. (state: [u32; 8], block: [u32; 16]) -> updated_state: [u32; 8].

use super::{ryan_sha256_constants::{MSG_BLOCK, STATE}, ryan_sha256_constants::K32X4};
use std::static_assert;

// ------------------- ALL THE SHA STUFF -------------------

/// TODO: This is extremely inefficient!!!
fn add_u32_with_wraparound(a: u32, b: u32) -> u32 {
    (((a as u64) + (b as u64)) % (1 << 32)) as u32
}

// ------ Vec element-wise operations ------
/// Just computes an element-wise sum over two fixed-length slices.
fn vec_eltwise_add_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [
        add_u32_with_wraparound(a[0], b[0]),
        add_u32_with_wraparound(a[1], b[1]),
        add_u32_with_wraparound(a[2], b[2]),
        add_u32_with_wraparound(a[3], b[3]),
    ]
}

fn vec_shift_left_u32(a: [u32; 4], shift_offset: u8) -> [u32; 4] {
    [a[0] >> shift_offset, a[1] >> shift_offset, a[2] >> shift_offset, a[3] >> shift_offset]
}

fn vec_shift_right_u32(a: [u32; 4], shift_offset: u8) -> [u32; 4] {
    [a[0] << shift_offset, a[1] << shift_offset, a[2] << shift_offset, a[3] << shift_offset]
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
    let left_side_already_moved = val >> (32 - rotation_amt);
    let right_side_already_moved = val << rotation_amt;
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

fn bool3ary_202(a: u32, b: u32, c: u32) -> u32 {
    c ^ (a & (b ^ c))
}

fn bool3ary_232(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

fn sha256swap(v0: [u32; 4]) -> [u32; 4] {
    [v0[2], v0[3], v0[0], v0[1]]
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
    rotate_right_via_shift_u32(a, 17) ^ rotate_right_via_shift_u32(a, 19) ^ a >> 10
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

    let w16 = add_u32_with_wraparound(x0, sigma1(w14));
    let w17 = add_u32_with_wraparound(x1, sigma1(w15));
    let w18 = add_u32_with_wraparound(x2, sigma1(w16));
    let w19 = add_u32_with_wraparound(x3, sigma1(w17));

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

// ---------- Round functions ---------

/// Note: This returns `(updated_w4, updated_abef, updated_cdgh)` as a tuple.
fn schedule_rounds4(
    abef: [u32; 4],
    cdgh: [u32; 4],
    w0: [u32; 4],
    w1: [u32; 4],
    w2: [u32; 4],
    w3: [u32; 4],
    _w4: [u32; 4],
    round_idx: u32,
) -> ([u32; 4], [u32; 4], [u32; 4]) {
    let updated_w4 = schedule(w0, w1, w2, w3);

    let (updated_abef, updated_cdgh) = rounds4(abef, cdgh, updated_w4, round_idx);
    (updated_w4, updated_abef, updated_cdgh)
}

fn sha256_digest_round_x2(cdgh: [u32; 4], abef: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    // Choose, MD5F, SHA1C

    // --- Doing manual unpacking here ---
    // let [_, _, wk1, wk0] = wk;
    // let [a0, b0, e0, f0] = abef;
    // let [c0, d0, g0, h0] = cdgh;
    let wk1 = wk[2];
    let wk0 = wk[3];

    let a0 = abef[0];
    let b0 = abef[1];
    let e0 = abef[2];
    let f0 = abef[3];

    let c0 = cdgh[0];
    let d0 = cdgh[1];
    let g0 = cdgh[2];
    let h0 = cdgh[3];

    // a round
    // --- Take the `e` state and compute a "permutation" thingy on itself ---
    // --- Then add the boolean functions against `e, f, g` ---
    // --- Then add the block's 0th element ---
    // --- Then add the `h` state ---
    let x0 = add_u32_with_wraparound(
        big_sigma1(e0),
        add_u32_with_wraparound(bool3ary_202(e0, f0, g0), add_u32_with_wraparound(wk0, h0)),
    );

    // --- Take the `a` state and compute a "permutation" ---
    // --- Then add the boolean functions against `a, b, c` ---
    // --- Rotate everything right one for (a, b, c, d) and (e, f, g, h) ---
    // --- Then set the first output to be the new `a` and the second output to be the new `d` ---
    let y0 = add_u32_with_wraparound(big_sigma0(a0), bool3ary_232(a0, b0, c0));

    let (a1, b1, c1, d1, e1, f1, g1, h1) =
        (add_u32_with_wraparound(x0, y0), a0, b0, c0, add_u32_with_wraparound(x0, d0), e0, f0, g0);

    // a round
    let x1 = add_u32_with_wraparound(
        big_sigma1(e1),
        add_u32_with_wraparound(bool3ary_202(e1, f1, g1), add_u32_with_wraparound(wk1, h1)),
    );
    let y1 = add_u32_with_wraparound(big_sigma0(a1), bool3ary_232(a1, b1, c1));
    let (a2, b2, _, _, e2, f2, _, _) =
        (add_u32_with_wraparound(x1, y1), a1, b1, c1, add_u32_with_wraparound(x1, d1), e1, f1, g1);

    // --- Recall that the return value is either `abef` or `cdgh` ---
    [a2, b2, e2, f2]
}

/// Slight modification to the Rust macro -- we instead directly return `abef, cdgh` as a tuple
fn rounds4(abef: [u32; 4], cdgh: [u32; 4], rest: [u32; 4], round_idx: u32) -> ([u32; 4], [u32; 4]) {
    // --- First thing is to add a bunch of constants to `w0` ---
    // Note that `add` is just element-wise addition
    let t1 = vec_eltwise_add_u32(rest, K32X4[round_idx]);

    // --- We update the cdgh part of the state (this is roughly two rounds) ---
    let updated_cdgh = sha256_digest_round_x2(cdgh, abef, t1);

    // --- [0, 1, 2, 3] --> [2, 3, 0, 1] ---
    let t2 = sha256swap(t1);
    // --- We update the abef part of the state (again, roughly two rounds) ---
    let updated_abef = sha256_digest_round_x2(abef, updated_cdgh, t2);
    (updated_abef, updated_cdgh)
}

/// This should be identical in functionality to `std::hash::sha256_compression`
/// In particular, we return the updated state
pub fn ryan_sha256_digest_block_u32(state: STATE, block: MSG_BLOCK) -> [u32; 8] {
    // --- [a, b, e, f, c, d, g, h] ---
    let mut abef = [state[0], state[1], state[4], state[5]];
    let mut cdgh = [state[2], state[3], state[6], state[7]];

    // Rounds 0..64
    let mut w0 = [block[3], block[2], block[1], block[0]];
    let mut w1 = [block[7], block[6], block[5], block[4]];
    let mut w2 = [block[11], block[10], block[9], block[8]];
    let mut w3 = [block[15], block[14], block[13], block[12]];
    let mut w4: [u32; 4] = [0, 0, 0, 0];

    let (abef, cdgh) = rounds4(abef, cdgh, w0, 0);
    let (abef, cdgh) = rounds4(abef, cdgh, w1, 1);
    let (abef, cdgh) = rounds4(abef, cdgh, w2, 2);
    let (abef, cdgh) = rounds4(abef, cdgh, w3, 3);

    let (w4, abef, cdgh) = schedule_rounds4(abef, cdgh, w0, w1, w2, w3, w4, 4);
    let (w0, abef, cdgh) = schedule_rounds4(abef, cdgh, w1, w2, w3, w4, w0, 5);
    let (w1, abef, cdgh) = schedule_rounds4(abef, cdgh, w2, w3, w4, w0, w1, 6);
    let (w2, abef, cdgh) = schedule_rounds4(abef, cdgh, w3, w4, w0, w1, w2, 7);
    let (w3, abef, cdgh) = schedule_rounds4(abef, cdgh, w4, w0, w1, w2, w3, 8);
    let (w4, abef, cdgh) = schedule_rounds4(abef, cdgh, w0, w1, w2, w3, w4, 9);
    let (w0, abef, cdgh) = schedule_rounds4(abef, cdgh, w1, w2, w3, w4, w0, 10);
    let (w1, abef, cdgh) = schedule_rounds4(abef, cdgh, w2, w3, w4, w0, w1, 11);
    let (w2, abef, cdgh) = schedule_rounds4(abef, cdgh, w3, w4, w0, w1, w2, 12);
    let (w3, abef, cdgh) = schedule_rounds4(abef, cdgh, w4, w0, w1, w2, w3, 13);
    let (w4, abef, cdgh) = schedule_rounds4(abef, cdgh, w0, w1, w2, w3, w4, 14);
    let (_w0, abef, cdgh) = schedule_rounds4(abef, cdgh, w1, w2, w3, w4, w0, 15);

    // --- Again, manual unpacking ---
    // let [a, b, e, f] = abef;
    // let [c, d, g, h] = cdgh;
    let a = abef[0];
    let b = abef[1];
    let e = abef[2];
    let f = abef[3];

    let c = cdgh[0];
    let d = cdgh[1];
    let g = cdgh[2];
    let h = cdgh[3];

    // --- Return updated state ---
    [
        add_u32_with_wraparound(state[0], a),
        add_u32_with_wraparound(state[1], b),
        add_u32_with_wraparound(state[2], c),
        add_u32_with_wraparound(state[3], d),
        add_u32_with_wraparound(state[4], e),
        add_u32_with_wraparound(state[5], f),
        add_u32_with_wraparound(state[6], g),
        add_u32_with_wraparound(state[7], h),
    ]
}
