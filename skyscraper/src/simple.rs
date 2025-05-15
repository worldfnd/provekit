use {crate::generic, block_multiplier::scalar_sqr as square};

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    generic::compress_many(
        |input| generic::compress(|x| [square(x[0])], input),
        messages,
        hashes,
    )
}

#[inline(always)]
pub fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    generic::compress(|x| [square(x[0])], [[l, r]])[0]
}

#[cfg(test)]
mod tests {
    use {super::*, proptest::proptest};

    #[test]
    fn test_eq_ref() {
        proptest!(|(l: [u64; 4], r: [u64; 4])| {
            let e = crate::reference::compress(l, r);
            let r = compress(l, r);
            assert_eq!(r, e);
        });
    }
}
