//! Constants for RNE Montgomery multiplication over the BN254 scalar field.

use crate::pow_2;

/// Montgomery reduction constant: `-p⁻¹ mod 2⁵¹`
pub const U51_NP0: u64 = 0x1f593efffffff;

/// BN254 scalar field prime
pub const U51_P: [u64; 5] = [
    0x1f593f0000001,
    0x10f372e12287c,
    0x6056174a0cfa1,
    0x014dc2822db40,
    0x30644e72e131a,
];

/// Bit mask for 51-bit limbs.
pub const MASK51: u64 = 2_u64.pow(51) - 1;

/// Reduction constants: `RHO_i = 2^(51*i) * 2^255 mod p` in 51-bit limbs.
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
pub const C3: f64 = pow_2(52) + pow_2(51);
