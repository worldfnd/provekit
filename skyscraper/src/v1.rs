use {
    crate::{
        arithmetic::add,
        bar::bar,
        generic,
        reduce::{reduce, reduce_partial, reduce_partial_add_rc},
    },
    block_multiplier::scalar_sqr as square,
};

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    generic::compress_many(
        |input: [[[u64; 4]; 2]; 1]| [compress(input[0][0], input[0][1])],
        messages,
        hashes,
    )
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
