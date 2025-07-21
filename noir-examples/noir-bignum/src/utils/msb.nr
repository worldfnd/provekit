/// Multiple entires in the `MUL_DE_BRUIJN_BIT` list do not map to a valid output of `v * 0x6c04f118e9966f6b`.
/// This is a dummy value to fill the gaps in the map.
global n1: u32 = 0xffffffff;

global MUL_DE_BRUIJN_BIT: [u32; 128] = [
    0, // change to 1 if you want bitSize(0) = 1
    48, n1, n1, 31, n1, 15, 51, n1, 63, 5, n1, n1, n1, 19, n1, 23, 28, n1, n1, n1, 40, 36, 46, n1,
    13, n1, n1, n1, 34, n1, 58, n1, 60, 2, 43, 55, n1, n1, n1, 50, 62, 4, n1, 18, 27, n1, 39, 45,
    n1, n1, 33, 57, n1, 1, 54, n1, 49, n1, 17, n1, n1, 32, n1, 53, n1, 16, n1, n1, 52, n1, n1, n1,
    64, 6, 7, 8, n1, 9, n1, n1, n1, 20, 10, n1, n1, 24, n1, 29, n1, n1, 21, n1, 11, n1, n1, 41, n1,
    25, 37, n1, 47, n1, 30, 14, n1, n1, n1, n1, 22, n1, n1, 35, 12, n1, n1, n1, 59, 42, n1, n1, 61,
    3, 26, 38, 44, n1, 56,
];

pub unconstrained fn get_msb64(x: u64) -> u32 {
    let mut v = x;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    MUL_DE_BRUIJN_BIT[(std::wrapping_mul(v, 0x6c04f118e9966f6b)) >> 57]
}

// 1100
