use {
    crate::{
        arithmetic::less_than,
        constants::MODULUS,
        reduce::{reduce_1, reduce_partial},
    },
    zerocopy::transmute,
};

/// Applies the non-algebraic bar operation.
///
/// Requires input to be in [0, 2M)
/// Output is in range [0, M + ϵ]
#[inline(always)]
pub fn bar(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[2]));
    let x = reduce_1(x);
    let x = [x[2], x[3], x[0], x[1]];

    let bytes: [u8; 32] = transmute!(x);
    let bytes = bytes.map(sbox);
    let x = transmute!(bytes);

    // let x = x.map(sbox_8);

    // let limbs: [u128; 2] = transmute!(x);
    // let limbs = limbs.map(sbox_16);
    // let x = transmute!(limbs);

    reduce_partial(x)
}

/// Vectorized version of [`bar`]
#[inline(always)]
pub fn barv<const N: usize>(x: [[u64; 4]; N]) -> [[u64; 4]; N] {
    x.map(bar)
}

#[inline(always)]
pub fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

// From <https://extgit.isec.tugraz.at/krypto/zkfriendlyhashzoo/-/blob/master/plain_impls/src/fields/skyscraper_extension.rs?ref_type=heads>
#[inline(always)]
pub fn sbox_16(value: u128) -> u128 {
    let t1 = ((value & 0x80808080808080808080808080808080) >> 7)
        | ((value & 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f) << 1); // circular left rot by 1
    let t2 = ((value & 0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0) >> 6)
        | ((value & 0x3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f) << 2); // circular left rot by 2
    let t3 = ((value & 0xe0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0) >> 5)
        | ((value & 0x1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f) << 3); // circular left rot by 3
    let tmp = (!t1 & t2 & t3) ^ value;
    ((tmp & 0x80808080808080808080808080808080) >> 7)
        | ((tmp & 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f) << 1) // Final left rot by
                                                            // 1
}

#[inline(always)]
pub fn sbox_8(value: u64) -> u64 {
    let t1 = ((value & 0x8080808080808080) >> 7) | ((value & 0x7f7f7f7f7f7f7f7f) << 1); // circular left rot by 1
    let t2 = ((value & 0xc0c0c0c0c0c0c0c0) >> 6) | ((value & 0x3f3f3f3f3f3f3f3f) << 2); // circular left rot by 2
    let t3 = ((value & 0xe0e0e0e0e0e0e0e0) >> 5) | ((value & 0x1f1f1f1f1f1f1f1f) << 3); // circular left rot by 3
    let tmp = (!t1 & t2 & t3) ^ value;
    ((tmp & 0x8080808080808080) >> 7) | ((tmp & 0x7f7f7f7f7f7f7f7f) << 1) // Final left rot by
                                                                          // 1
}

#[cfg(test)]
mod tests {
    use {crate::reference::sbox, proptest::proptest};

    #[test]
    fn test_sbox_ref() {
        proptest!(|(x: u8)| {
            assert_eq!(sbox(x), crate::reference::sbox(x));
        });
    }
}
