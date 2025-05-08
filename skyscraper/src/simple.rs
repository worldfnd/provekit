use {
    crate::constants::{MODULUS, ROUND_CONSTANTS},
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

#[inline(always)]
fn add(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (r0, carry) = l[0].overflowing_add(r[0]);
    let (r1, carry) = l[1].carrying_add(r[1], carry);
    let (r2, carry) = l[2].carrying_add(r[2], carry);
    let (r3, carry) = l[3].carrying_add(r[3], carry);
    debug_assert!(!carry);
    [r0, r1, r2, r3]
}

#[inline(always)]
fn bar(x: [u64; 4]) -> [u64; 4] {
    let x = reduce(x);
    let x = [x[2], x[3], x[0], x[1]];
    let bytes: [u8; 32] = transmute!(x);
    let bytes = bytes.map(sbox);
    reduce_partial(transmute!(bytes))
}

#[inline(always)]
fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

fn range(x: [u64; 4]) -> usize {
    (x[3] / (MODULUS[1][3] + 1)) as usize
}

/// Reduce input to [0, M + 2^192]
#[inline(always)]
fn reduce_partial(x: [u64; 4]) -> [u64; 4] {
    let multiple = (x[3] / (MODULUS[1][3] + 1)) as usize;
    let (r0, borrow) = x[0].overflowing_sub(MODULUS[multiple][0]);
    let (r1, borrow) = x[1].borrowing_sub(MODULUS[multiple][1], borrow);
    let (r2, borrow) = x[2].borrowing_sub(MODULUS[multiple][2], borrow);
    let (r3, borrow) = x[3].borrowing_sub(MODULUS[multiple][3], borrow);
    debug_assert!(!borrow);
    debug_assert_eq!(range([r0, r1, r2, r3]), 0);
    [r0, r1, r2, r3]
}

/// Reduce input to [0, M)
#[inline(always)]
fn reduce(x: [u64; 4]) -> [u64; 4] {
    let x = reduce_partial(x);
    let (r0, borrow) = x[0].overflowing_sub(MODULUS[1][0]);
    let (r1, borrow) = x[1].borrowing_sub(MODULUS[1][1], borrow);
    let (r2, borrow) = x[2].borrowing_sub(MODULUS[1][2], borrow);
    let (r3, borrow) = x[3].borrowing_sub(MODULUS[1][3], borrow);
    if borrow {
        x
    } else {
        [r0, r1, r2, r3]
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::Fr,
        ark_ff::{BigInt, PrimeField},
        proptest::proptest,
    };

    #[test]
    fn test_reduce() {
        proptest!(|(x: [u64; 4])| {
            let e = Fr::new(BigInt(x)).into_bigint().0;
            let r = reduce(x);
            assert_eq!(r, e);
        })
    }

    #[test]
    fn eq_ref() {
        proptest!(|(l: [u64; 4], r: [u64; 4])| {
            let e = crate::reference::compress(l, r);
            let r = compress(l, r);
            assert_eq!(r, e);
        });
    }
}
