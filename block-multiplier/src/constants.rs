pub const U64_NP0: u64 = 0xc2e1f593efffffff;

pub const U64_P: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

pub const U64_2P: [u64; 4] = [
    0x87c3eb27e0000002,
    0x5067d090f372e122,
    0x70a08b6d0302b0ba,
    0x60c89ce5c2634053,
];

// R mod P
pub const U64_R: [u64; 4] = [
    0xac96341c4ffffffb,
    0x36fc76959f60cd29,
    0x666ea36f7879462e,
    0x0e0a77c19a07df2f,
];

// R^2 mod P
pub const U64_R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

// R^-1 mod P
pub const U64_R_INV: [u64; 4] = [
    0xdc5ba0056db1194e,
    0x090ef5a9e111ec87,
    0xc8260de4aeb85d5d,
    0x15ebf95182c5551c,
];

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
    0x060c89ce5c263,
];

pub const F52_P: [f64; 5] = [
    0x1f593f0000001_u64 as f64,
    0x4879b9709143e_u64 as f64,
    0x181585d2833e8_u64 as f64,
    0xa029b85045b68_u64 as f64,
    0x030644e72e131_u64 as f64,
];

pub const MASK52: u64 = 2_u64.pow(52) - 1;
pub const MASK48: u64 = 2_u64.pow(48) - 1;

pub const U64_I1: [u64; 4] = [
    0x2d3e8053e396ee4d,
    0xca478dbeab3c92cd,
    0xb2d8f06f77f52a93,
    0x24d6ba07f7aa8f04,
];
pub const U64_I2: [u64; 4] = [
    0x18ee753c76f9dc6f,
    0x54ad7e14a329e70f,
    0x2b16366f4f7684df,
    0x133100d71fdf3579,
];

pub const U64_I3: [u64; 4] = [
    0x9bacb016127cbe4e,
    0x0b2051fa31944124,
    0xb064eea46091c76c,
    0x2b062aaa49f80c7d,
];
pub const U64_MU0: u64 = 0xc2e1f593efffffff;

// -- [FP SIMD CONSTANTS]
// --------------------------------------------------------------------------
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

pub const C1: f64 = pow_2(104); // 2.0^104
pub const C2: f64 = pow_2(104) + pow_2(52); // 2.0^104 + 2.0^52
// const C3: f64 = pow_2(52); // 2.0^52
// -------------------------------------------------------------------------------------------------

const fn pow_2(n: u32) -> f64 {
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = ((n as u64 + 1023) & 0x7ff) << 52;
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
