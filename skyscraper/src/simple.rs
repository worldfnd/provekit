use {
    crate::{
        arithmetic::add,
        bar::bar,
        constants::ROUND_CONSTANTS,
        reduce::{reduce, reduce_partial, reduce_partial_add_rc},
    },
    block_multiplier::scalar_sqr,
    zerocopy::transmute,
};

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    assert_eq!(messages.len() % 64, 0);
    assert_eq!(hashes.len() % 32, 0);
    for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
        let message: [u8; 64] = message.try_into().unwrap();
        let [l, r] = transmute!(message);
        let h = compress(l, r);
        let h: [u8; 32] = transmute!(h);
        hash.copy_from_slice(h.as_slice());
    }
}

pub fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (l, r) = (reduce_partial(l), reduce_partial(r));
    let t = l;
    let (l, r) = (add(r, square(l)), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[1]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[2]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[3]), l);
    let (l, r) = (reduce_partial(l), reduce_partial(r));
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[4]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[5]), l);
    let (l, r) = (add(add(r, bar(l)), ROUND_CONSTANTS[6]), l);
    let (l, r) = (add(add(r, bar(l)), ROUND_CONSTANTS[7]), l);
    let (l, r) = (reduce_partial(l), reduce_partial(r));
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[8]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[9]), l);
    let (l, r) = (add(add(r, bar(l)), ROUND_CONSTANTS[10]), l);
    let (l, r) = (add(add(r, bar(l)), ROUND_CONSTANTS[11]), l);
    let (l, r) = (reduce_partial(l), reduce_partial(r));
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[12]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[13]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[14]), l);
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[15]), l);
    let (l, r) = (reduce_partial(l), reduce_partial(r));
    let (l, r) = (add(add(r, square(l)), ROUND_CONSTANTS[16]), l);
    reduce(add(add(r, square(l)), t))
}

#[inline(always)]
fn square(x: [u64; 4]) -> [u64; 4] {
    let x = scalar_sqr(x);
    reduce_partial(x)
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
