use {
    crate::reduce::{reduce_1, reduce_partial},
    zerocopy::transmute,
};

/// Applies the non-algebraic bar operation.
///
/// Requires input to be in [0, 2M)
/// Output is in range [0, M + ϵ]
#[inline(always)]
pub fn bar(x: [u64; 4]) -> [u64; 4] {
    let x = reduce_1(x);
    let x = [x[2], x[3], x[0], x[1]];
    let bytes: [u8; 32] = transmute!(x);
    let bytes = bytes.map(sbox);
    reduce_partial(transmute!(bytes))
}

#[inline(always)]
pub fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
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
