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

// BOUNDS
/// Upper bound of 2**256-2p
pub const OUTPUT_MAX: [u64; 4] = [
    0x783c14d81ffffffe,
    0xaf982f6f0c8d1edd,
    0x8f5f7492fcfd4f45,
    0x9f37631a3d9cbfac,
];
