use crate::constants::TWO_POW_120;

unconstrained fn split_120_bits(mut x: Field) -> (u128, u128) {
    // Here we're taking advantage of truncating 128 bit limbs from the input field
    // and then subtracting them from the input such that the field division is equivalent to integer division.
    let low = (x as u128) % TWO_POW_120;
    let high = ((x - low as Field) / TWO_POW_120 as Field) as u128;
    (low, high)
}

pub(crate) unconstrained fn __normalize_limbs<let N: u32>(
    input: [Field; N],
    range: u32,
) -> [u128; N] {
    let mut normalized: [u128; N] = [0; N];
    let mut next: Field = input[0];
    for i in 0..(range - 1) {
        let (lo, hi) = split_120_bits(next);
        normalized[i] = lo as u128;
        next = input[i + 1] + hi as Field;
    }
    {
        let (lo, hi) = split_120_bits(next);

        normalized[range - 1] = lo as u128;
        assert(hi == 0);
    }
    normalized
}
