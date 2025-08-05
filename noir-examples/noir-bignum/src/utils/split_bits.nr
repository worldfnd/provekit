use crate::constants::TWO_POW_32;

unconstrained fn split_32_bits(mut x: u128) -> (u64, u64) {
    let low = ((x) % (TWO_POW_32 as u128)) as u64;
    let high = ((x - low as u128) / TWO_POW_32 as u128) as u64;
    (low, high)
}

pub unconstrained fn __normalize_limbs<let N: u32>(input: [u128; N], range: u32) -> [u64; N] {
    let mut normalized: [u64; N] = [0; N];
    let mut next: u128 = input[0];
    for i in 0..(range - 1) {
        let (lo, hi) = split_32_bits(next);
        normalized[i] = lo;
        next = input[i + 1] + hi as u128;
    }
    {
        let (lo, hi) = split_32_bits(next);
        normalized[range - 1] = lo;
        // TODO: Figure out why the last limb does have an overflow
        assert(hi == 0);
    }
    normalized
}
