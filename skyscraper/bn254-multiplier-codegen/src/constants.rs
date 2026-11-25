// -- [Scalar CONSTANTS] -- //

pub use bn254_multiplier_constants::{
    I1_LIMB, I2_LIMB, I3_LIMB, MU0_LIMB, P_LIMB, U64_2P, U64_I1, U64_I2, U64_I3, U64_MU0, U64_P,
};

// -- [FP SIMD CONSTANTS] -- //

pub const U52_NP0: u64 = 0x1f593efffffff;
pub const U52_R2: [u64; 5] = [
    0x0b852d16da6f5,
    0xc621620cddce3,
    0xaf1b95343ffb6,
    0xc3c15e103e7c2,
    0x00281528fa122,
];

pub const U52_P: [u64; 5] = [
    0x1f593f0000001,
    0x4879b9709143e,
    0x181585d2833e8,
    0xa029b85045b68,
    0x030644e72e131,
];

pub const U52_2P: [u64; 5] = [
    0x3eb27e0000002,
    0x90f372e12287c,
    0x302b0ba5067d0,
    0x405370a08b6d0,
    0x60c89ce5c263,
];

pub const RHO_1: [u64; 5] = [
    0x82e644ee4c3d2,
    0xf93893c98b1de,
    0xd46fe04d0a4c7,
    0x8f0aad55e2a1f,
    0x005ed0447de83,
];

pub const RHO_2: [u64; 5] = [
    0x74eccce9a797a,
    0x16ddcc30bd8a4,
    0x49ecd3539499e,
    0xb23a6fcc592b8,
    0x00e3bd49f6ee5,
];

pub const RHO_3: [u64; 5] = [
    0x0e8c656567d77,
    0x430d05713ae61,
    0xea3ba6b167128,
    0xa7dae55c5a296,
    0x01b4afd513572,
];

pub const RHO_4: [u64; 5] = [
    0x22e2400e2f27d,
    0x323b46ea19686,
    0xe6c43f0df672d,
    0x7824014c39e8b,
    0x00c6b48afe1b8,
];

pub const MASK52: u64 = 2_u64.pow(52) - 1;

pub const C1: f64 = pow_2(104); // 2.0^104
pub const C2: f64 = pow_2(104) + pow_2(52); // 2.0^104 + 2.0^52

const fn pow_2(n: u32) -> f64 {
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = ((n as u64 + 1023) & 0x7ff) << 52;
    f64::from_bits(exp)
}
