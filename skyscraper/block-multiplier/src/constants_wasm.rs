// Double check if this is still correct
pub const U52_NP0: u64 = 0x1f593efffffff;

pub const U51_P: [u64; 5] = [
    0x1f593f0000001,
    0x10f372e12287c,
    0x6056174a0cfa1,
    0x014dc2822db40,
    0x30644e72e131a,
];

pub const F52_P: [f64; 5] = [
    0x1f593f0000001_u64 as f64,
    0x4879b9709143e_u64 as f64,
    0x181585d2833e8_u64 as f64,
    0xa029b85045b68_u64 as f64,
    0x030644e72e131_u64 as f64,
];

pub const MASK51: u64 = 2_u64.pow(51) - 1;

// -- [FP SIMD CONSTANTS]
// --------------------------------------------------------------------------

pub const RHO_1: [u64; 5] = [
    0x05cc89dc987a4,
    0x64e24f262c77a,
    0x237f02685263f,
    0x70aad55e2a1fd,
    0x0bda088fbd071,
];

pub const RHO_2: [u64; 5] = [
    0x3459f4a69e5e7,
    0x25faeea4c9ca7,
    0x3e771def3ca40,
    0x46003708f7bc8,
    0x088b040ada652,
];

pub const RHO_3: [u64; 5] = [
    0x76fe2f2b3ebb4,
    0x6d028b8f2441f,
    0x461c7904ae683,
    0x71824d0dd38b7,
    0x18c6b0be26ceb,
];

pub const RHO_4: [u64; 5] = [
    0x30bf04e2f27cc,
    0x039b11bea2ed3,
    0x2fb7665568cc8,
    0x0cc99c143d8f0,
    0x0523513296c10,
];

pub const C1: f64 = pow_2(103);
pub const C2: f64 = pow_2(103) + pow_2(52) + pow_2(51);

const fn pow_2(n: u32) -> f64 {
    assert!(n <= 1023);
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = (n as u64 + 1023) << 52;
    f64::from_bits(exp)
}

// BOUNDS
/// Upper bound of 2**256-2p
pub const OUTPUT_MAX: [u64; 4] = [
    0x783c14d81ffffffe,
    0xaf982f6f0c8d1edd,
    0x8f5f7492fcfd4f45,
    0x9f37631a3d9cbfac,
];
