use seq_macro::seq;

/// Bn254 scalar field modulus and multiples
#[rustfmt::skip]
pub const MODULUS: [[u64; 4]; 6] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029],
    [0x87c3eb27e0000002, 0x5067d090f372e122, 0x70a08b6d0302b0ba, 0x60c89ce5c2634053],
    [0xcba5e0bbd0000003, 0x789bb8d96d2c51b3, 0x28f0d12384840917, 0x912ceb58a394e07d],
    [0x0f87d64fc0000004, 0xa0cfa121e6e5c245, 0xe14116da06056174, 0xc19139cb84c680a6],
    [0x5369cbe3b0000005, 0xc903896a609f32d6, 0x99915c908786b9d1, 0xf1f5883e65f820d0],
];

/// Skyscaper round constants for Bn254-Fr and t=1.
///
/// In little-endian reduced non-Montgomery form.
///
/// Generated using reference sage implementation:
/// ```python
/// load('skyscraper.sage')
/// for n in map(int, Sky_BN254_1.rcons):
///     limbs = [(n >> (64 * i)) & (2**64 - 1) for i in range(4)]
///     hex_limbs = ', '.join(f"0x{l:016x}" for l in limbs)
///     print(f"    [{hex_limbs}],")
/// ```
#[rustfmt::skip]
pub const ROUND_CONSTANTS: [[u64; 4]; 18] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x903c4324270bd744, 0x873125f708a7d269, 0x081dd27906c83855, 0x276b1823ea6d7667],
    [0x7ac8edbb4b378d71, 0xe29d79f3d99e2cb7, 0x751417914c1a5a18, 0x0cf02bd758a484a6],
    [0xfa7adc6769e5bc36, 0x1c3f8e297cca387d, 0x0eb7730d63481db0, 0x25b0e03f18ede544],
    [0x57847e652f03cfb7, 0x33440b9668873404, 0x955a32e849af80bc, 0x002882fcbe14ae70],
    [0x979231396257d4d7, 0x29989c3e1b37d3c1, 0x12ef02b47f1277ba, 0x039ad8571e2b7a9c],
    [0xb5b48465abbb7887, 0xa72a6bc5e6ba2d2b, 0x4cd48043712f7b29, 0x1142d5410fc1fc1a],
    [0x7ab2c156059075d3, 0x17cb3594047999b2, 0x44f2c93598f289f7, 0x1d78439f69bc0bec],
    [0x05d7a965138b8edb, 0x36ef35a3d55c48b1, 0x8ddfb8a1ac6f1628, 0x258588a508f4ff82],
    [0x1596fb9afccb49e9, 0x9a7367d69a09a95b, 0x9bc43f6984e4c157, 0x13087879d2f514fe],
    [0x295ccd233b4109fa, 0xe1d72f89ed868012, 0x2e9e1eea4bc88a8e, 0x17dadee898c45232],
    [0x9a8590b4aa1f486f, 0xb75834b430e9130e, 0xb8e90b1034d5de31, 0x295c6d1546e7f4a6],
    [0x850adcb74c6eb892, 0x07699ef305b92fc3, 0x4ef96a2ba1720f2d, 0x1288ca0e1d3ed446],
    [0x01960f9349d1b5ee, 0x8ccad30769371c69, 0xe5c81e8991c98662, 0x17563b4d1ae023f3],
    [0x6ba01e9476b32917, 0xa1cb0a3add977bc9, 0x86815a945815f030, 0x2869043be91a1eea],
    [0x81776c885511d976, 0x7475d34f47f414e7, 0x5d090056095d96cf, 0x14941f0aff59e79a],
    [0xbc40b4fd8fc8c034, 0xbb7142c3cce4fd48, 0x318356758a39005a, 0x1ce337a190f4379f],
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
];

pub const MODULUS_N_MINUS_RC: [[[u64; 4]; 18]; 6] = [
    seq!(I in 0..18 { [#(const_minus(MODULUS[0], ROUND_CONSTANTS[I], true),)*] }),
    seq!(I in 0..18 { [#(const_minus(MODULUS[1], ROUND_CONSTANTS[I], false),)*] }),
    seq!(I in 0..18 { [#(const_minus(MODULUS[2], ROUND_CONSTANTS[I], false),)*] }),
    seq!(I in 0..18 { [#(const_minus(MODULUS[3], ROUND_CONSTANTS[I], false),)*] }),
    seq!(I in 0..18 { [#(const_minus(MODULUS[4], ROUND_CONSTANTS[I], false),)*] }),
    seq!(I in 0..18 { [#(const_minus(MODULUS[5], ROUND_CONSTANTS[I], false),)*] }),
];

const fn const_minus(l: [u64; 4], r: [u64; 4], may_borrow: bool) -> [u64; 4] {
    let (r0, borrow) = l[0].overflowing_sub(r[0]);
    let (r1, borrow) = l[1].borrowing_sub(r[1], borrow);
    let (r2, borrow) = l[2].borrowing_sub(r[2], borrow);
    let (r3, borrow) = l[3].borrowing_sub(r[3], borrow);
    assert!(!borrow || may_borrow);
    [r0, r1, r2, r3]
}
