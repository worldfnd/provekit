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
    0x1BB8E645AE216DA7,
    0x53FE3AB1E35C59E3,
    0x8C49833D53BB8085,
    0x0216D0B17F4E44A5,
];

// R^-1 mod P
pub const U64_R_INV: [u64; 4] = [
    0xdc5ba0056db1194e,
    0x090ef5a9e111ec87,
    0xc8260de4aeb85d5d,
    0x15ebf95182c5551c,
];

pub const U52_NP0: u64 = 0x1F593EFFFFFFF;
pub const U52_R2: [u64; 5] = [
    0x0B852D16DA6F5,
    0xC621620CDDCE3,
    0xAF1B95343FFB6,
    0xC3C15E103E7C2,
    0x00281528FA122,
];

pub const U52_P: [u64; 5] = [
    0x1F593F0000001,
    0x4879B9709143E,
    0x181585D2833E8,
    0xA029B85045B68,
    0x030644E72E131,
];

pub const U52_2P: [u64; 5] = [
    0x3EB27E0000002,
    0x90F372E12287C,
    0x302B0BA5067D0,
    0x405370A08B6D0,
    0x060C89CE5C263,
];

pub const F52_P: [f64; 5] = [
    0x1F593F0000001_u64 as f64,
    0x4879B9709143E_u64 as f64,
    0x181585D2833E8_u64 as f64,
    0xA029B85045B68_u64 as f64,
    0x030644E72E131_u64 as f64,
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
    0x9BACB016127CBE4E,
    0x0B2051FA31944124,
    0xB064EEA46091C76C,
    0x2B062AAA49F80C7D,
];
pub const U64_MU0: u64 = 0xc2e1f593efffffff;

// -- [FP SIMD CONSTANTS] --------------------------------------------------------------------------
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
    0x0E8C656567D77,
    0x430D05713AE61,
    0xEA3BA6B167128,
    0xA7DAE55C5A296,
    0x01B4AFD513572,
];

pub const RHO_4: [u64; 5] = [
    0x22E2400E2F27D,
    0x323B46EA19686,
    0xE6C43F0DF672D,
    0x7824014C39E8B,
    0x00C6B48AFE1B8,
];

pub const C1: f64 = pow_2(104); // 2.0^104
pub const C2: f64 = pow_2(104) + pow_2(52); // 2.0^104 + 2.0^52
// const C3: f64 = pow_2(52); // 2.0^52
// -------------------------------------------------------------------------------------------------

const fn pow_2(n: u32) -> f64 {
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = ((n as u64 + 1023) & 0x7FF) << 52;
    f64::from_bits(exp)
}
