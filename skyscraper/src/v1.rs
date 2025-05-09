use {
    crate::{
        arithmetic::add,
        bar::bar,
        reduce::{reduce, reduce_partial, reduce_partial_add_rc},
    },
    block_multiplier::scalar_sqr as square,
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
    let (l, r) = (reduce_partial(add(r, square(l))), l);
    let (l, r) = (reduce_partial_add_rc(add(r, square(l)), 1), l);
    let (l, r) = (reduce_partial_add_rc(add(r, bar(l)), 2), l);
    let (l, r) = (reduce_partial_add_rc(add(r, bar(l)), 3), l);
    let (l, r) = (reduce_partial_add_rc(add(r, square(l)), 4), l);
    let (l, r) = (reduce_partial_add_rc(add(r, square(l)), 5), l);
    let (l, r) = (reduce_partial_add_rc(add(r, bar(l)), 6), l);
    let (l, r) = (reduce_partial_add_rc(add(r, bar(l)), 7), l);
    let (l, r) = (reduce_partial_add_rc(add(r, square(l)), 8), l);
    reduce(add(add(r, square(l)), t))
}
