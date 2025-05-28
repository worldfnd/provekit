use {
    crate::generic,
    core::array,
    fp_rounding::{with_rounding_mode, RoundingGuard, Zero},
};

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    unsafe {
        with_rounding_mode((messages, hashes), move |guard, (messages, hashes)| {
            generic::compress_many(|input| compress(guard, input), messages, hashes)
        });
    }
}

#[inline(always)]
fn compress(guard: &RoundingGuard<Zero>, input: [[[u64; 4]; 2]; 4]) -> [[u64; 4]; 4] {
    generic::compress(|x| square(guard, x), input)
}

#[inline(always)]
fn square(guard: &RoundingGuard<Zero>, n: [[u64; 4]; 4]) -> [[u64; 4]; 4] {
    let [a, b, c, d] = n;
    let v = array::from_fn(|i| std::simd::u64x2::from_array([c[i], d[i]]));
    let (a, b, v) = block_multiplier::montgomery_square_interleaved_4(guard, a, b, v);
    let c = v.map(|e| e[0]);
    let d = v.map(|e| e[1]);
    [a, b, c, d]
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        proptest::{
            collection::vec,
            prelude::{any, Strategy},
            proptest,
        },
    };

    fn random_input() -> impl Strategy<Value = Vec<u8>> {
        (1usize..=10).prop_flat_map(|chunks| vec(any::<u8>(), chunks * 64))
    }

    #[test]
    fn test_eq_ref() {
        proptest!(|(input in random_input())| {
            let mut r = vec![0; input.len() / 2];
            let mut e = vec![0; input.len() / 2];
            crate::reference::compress_many(&input, &mut e);
            compress_many(&input, &mut r);
            assert_eq!(r, e);
        });
    }
}
