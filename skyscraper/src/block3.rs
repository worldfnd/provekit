use {
    crate::{
        arithmetic::addv,
        bar::barv,
        reduce::{reduce, reduce_partial, reduce_partial_add_rcv},
    },
    core::array,
    fp_rounding::{with_rounding_mode, RoundingGuard, Zero},
    zerocopy::transmute,
};

const N: usize = 3;

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    assert_eq!(messages.len() % 64, 0);
    assert_eq!(hashes.len() % 32, 0);
    assert_eq!(hashes.len() * 2, messages.len());

    let count = hashes.len() / 32;
    let tail = count % N;
    let blocks = count - tail;
    unsafe {
        with_rounding_mode((messages, hashes), |guard, (messages, hashes)| {
            let (msg_blocks, msg_tail) = messages.split_at(blocks * 64);
            let (hsh_blocks, hsh_tail) = hashes.split_at_mut(blocks * 32);
            for (message, hash) in msg_blocks
                .chunks_exact(64 * N)
                .zip(hsh_blocks.chunks_exact_mut(32 * N))
            {
                let message: [u8; 64 * N] = message.try_into().unwrap();
                let input = transmute!(message);
                let h = compress(guard, input);
                let h: [u8; 32 * N] = transmute!(h);
                hash.copy_from_slice(h.as_slice());
            }
            if tail > 0 {
                let mut input = [[[0_u64; 4]; 2]; N];
                for (i, msg) in msg_tail.chunks_exact(64).enumerate() {
                    let msg: [u8; 64] = msg.try_into().unwrap();
                    input[i] = transmute!(msg);
                }
                let h = compress(guard, input);
                let h: [u8; 32 * N] = transmute!(h);
                hsh_tail.copy_from_slice(&h[..tail * 32]);
            }
        });
    }
}

#[inline(always)]
fn compress(guard: &RoundingGuard<Zero>, input: [[[u64; 4]; 2]; N]) -> [[u64; 4]; N] {
    let l = input.map(|e| e[0]).map(reduce_partial);
    let r = input.map(|e| e[1]).map(reduce_partial);
    let t = l;
    let (l, r) = (addv(r, square(guard, l)).map(reduce_partial), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 1), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 2), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 3), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 4), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 5), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 6), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 7), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 8), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 9), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 10), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 11), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 12), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 13), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 14), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 15), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(guard, l)), 16), l);
    addv(addv(r, square(guard, l)), t).map(reduce)
}

#[inline(always)]
fn square(guard: &RoundingGuard<Zero>, n: [[u64; 4]; N]) -> [[u64; 4]; N] {
    let [a, b, c] = n;
    let v = array::from_fn(|i| std::simd::u64x2::from_array([b[i], c[i]]));
    let (a, v) = block_multiplier::montgomery_interleaved_3(guard, a, a, v, v);
    let b = v.map(|e| e[0]);
    let c = v.map(|e| e[1]);
    [a, b, c]
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
