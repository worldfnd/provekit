use {
    crate::SmolHasher,
    bytemuck::{cast, cast_ref, cast_slice_mut, checked::cast_mut},
    hex_literal::hex,
    num_traits::WrappingMul,
    std::fmt::Display,
};

/// Limbs in little-endian order.
type U256 = [u64; 4];

// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const MODULUS: U256 = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];
const INV: u64 = 0xc2e1f593efffffff;

const RC: [U256; 8] = [
    [0; 4], [0; 4], [0; 4], [0; 4], [0; 4], [0; 4], [0; 4], [0; 4],
];

const SBOX: [u8; 256] = hex!("00020416080a2c2e10121406585a5c5e20222436282a0c0eb0b2b4a6b8babcbe40424456484a6c6e50525446181a1c1e61636577696b4d4f71737567797b7d7f80828496888aacae90929486d8dadcdea0a2a4b6a8aa8c8e30323426383a3c3ec2c0c6d4cac8eeecd2d0d6c49a989e9ce2e0e6f4eae8ceccf2f0f6e4faf8fefc010b051709032d2f111b150759535d5f212b253729230d0fb1bbb5a7b9b3bdbf414b455749436d6f515b554719131d1f606a647668624c4e707a746678727c7e858b81978d83a9af959b9187ddd3d9dfa5aba1b7ada3898f353b31273d33393fc5cbc1d7cdc3e9efd5dbd1c79d93999fe5ebe1f7ede3c9cff5fbf1e7fdf3f9ff");

pub struct Skyscraper;

impl Display for Skyscraper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "skyscraper-bn254-portable")
    }
}

impl SmolHasher for Skyscraper {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let a: U256 = cast::<[u8; 32], U256>(message[32..64].try_into().unwrap());
            let b: U256 = cast::<[u8; 32], U256>(message[32..64].try_into().unwrap());
            let c = compress(a, b);
            hash.copy_from_slice(cast_ref::<U256, [u8; 32]>(&c));
        }
    }
}

fn compress(l: U256, r: U256) -> U256 {
    let a = l;
    let (l, r) = (square_add_add_redc(r, [0; 4], l), l);
    let (l, r) = (square_add_add_redc(r, RC[0], l), l);
    let (l, r) = (r + bar(l) + RC[1], l);
    let (l, r) = (r + bar(l) + RC[2], l);
    let (l, r) = (square_add_add_redc(r, RC[3], l), l);
    let (l, r) = (square_add_add_redc(r, RC[4], l), l);
    let (l, r) = (r + bar(l) + RC[5], l);
    let (l, r) = (r + bar(l) + RC[6], l);
    let (l, r) = (square_add_add_redc(r, RC[7], l), l);
    square_add_add_redc(r, a, l)
}

/// Montgomery squaring. Computes REDC(a + b + n*n)
/// https://hackmd.io/@gnark/modular_multiplication
/// The input and output arguments do not need to be fully reduced.
fn square_add_add_redc(a: U256, b: U256, n: U256) -> U256 {
    square_redc(a)
}

/// Requires a to be fully reduced.
/// Output is not reduced.
fn bar(mut a: U256) -> U256 {
    let bytes: &mut [u8; 32] = cast_mut(&mut a);

    // Cyclic rotate by 16 bytes.
    let (left, right) = bytes.split_at_mut(16);
    left.swap_with_slice(right);

    // Apply SBox.
    bytes.iter_mut().for_each(|b| *b = SBOX[*b as usize]);

    // Recompose
    a

    // Reduce
}

#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn square_redc(a: [u64; 4]) -> [u64; 4] {
    debug_assert!(is_reduced(a));

    let (r0, carry) = carrying_mul_add(a[0], a[0], 0, 0);
    let (r1, carry_lo, carry_hi) = carrying_double_mul_add(a[0], a[1], 0, carry, false);
    let (r2, carry_lo, carry_hi) = carrying_double_mul_add(a[0], a[2], 0, carry_lo, carry_hi);
    let (r3, r4, _) = carrying_double_mul_add(a[0], a[3], 0, carry_lo, carry_hi);

    // Add m times modulus to result and shift one limb
    let m = INV.wrapping_mul(r0);
    let (_, carry) = carrying_mul_add(m, MODULUS[0], r0, 0);
    let (r0, carry) = carrying_mul_add(m, MODULUS[1], r1, carry);
    let (r1, carry) = carrying_mul_add(m, MODULUS[2], r2, carry);
    let (r2, carry) = carrying_mul_add(m, MODULUS[3], r3, carry);
    let r3 = r4 + carry;

    let (r1, carry) = carrying_mul_add(a[1], a[1], r1, 0);
    let (r2, carry_lo, carry_hi) = carrying_double_mul_add(a[1], a[2], r2, carry, false);
    let (r3, r4, _) = carrying_double_mul_add(a[1], a[3], r3, carry_lo, carry_hi);

    let m = INV.wrapping_mul(r0);
    let (_, carry) = carrying_mul_add(m, MODULUS[0], r0, 0);
    let (r0, carry) = carrying_mul_add(m, MODULUS[1], r1, carry);
    let (r1, carry) = carrying_mul_add(m, MODULUS[2], r2, carry);
    let (r2, carry) = carrying_mul_add(m, MODULUS[3], r3, carry);
    let r3 = r4 + carry;

    let (r2, carry) = carrying_mul_add(a[2], a[2], r2, 0);
    let (r3, r4, _) = carrying_double_mul_add(a[2], a[3], r3, carry, false);

    let m = INV.wrapping_mul(r0);
    let (_, carry) = carrying_mul_add(m, MODULUS[0], r0, 0);
    let (r0, carry) = carrying_mul_add(m, MODULUS[1], r1, carry);
    let (r1, carry) = carrying_mul_add(m, MODULUS[2], r2, carry);
    let (r2, carry) = carrying_mul_add(m, MODULUS[3], r3, carry);
    let r3 = r4 + carry;

    let (r3, r4) = carrying_mul_add(a[3], a[3], r3, 0);

    let m = INV.wrapping_mul(r0);
    let (_, carry) = carrying_mul_add(m, MODULUS[0], r0, 0);
    let (r0, carry) = carrying_mul_add(m, MODULUS[1], r1, carry);
    let (r1, carry) = carrying_mul_add(m, MODULUS[2], r2, carry);
    let (r2, carry) = carrying_mul_add(m, MODULUS[3], r3, carry);
    let r3 = r4 + carry;

    reduce1_carry([r0, r1, r2, r3], false)
}

#[inline]
#[must_use]
fn is_reduced(n: [u64; 4]) -> bool {
    for (lhs, rhs) in zip(n.iter().rev(), MODULUS.iter().rev()) {
        match lhs.cmp(rhs) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    // lhs == rhs
    false
}

#[inline]
#[must_use]
#[allow(clippy::needless_bitwise_bool)]
fn reduce1_carry(value: [u64; 4], carry: bool) -> [u64; 4] {
    let (reduced, borrow) = sub(value, modulus);
    // TODO: Ideally this turns into a cmov, which makes the whole mul_redc constant
    // time.
    if carry | !borrow {
        reduced
    } else {
        value
    }
}

/// Compute `lhs * rhs + add + carry`.
/// The output can not overflow for any input values.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
const fn carrying_mul_add(lhs: u64, rhs: u64, add: u64, carry: u64) -> (u64, u64) {
    let wide = (lhs as u128)
        .wrapping_mul(rhs as u128)
        .wrapping_add(add as u128)
        .wrapping_add(carry as u128);
    (wide as u64, (wide >> 64) as u64)
}

/// Compute `2 * lhs * rhs + add + carry_lo + 2^64 * carry_hi`.
/// The output can not overflow for any input values.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
const fn carrying_double_mul_add(
    lhs: u64,
    rhs: u64,
    add: u64,
    carry_lo: u64,
    carry_hi: bool,
) -> (u64, u64, bool) {
    let wide = (lhs as u128).wrapping_mul(rhs as u128);
    let (wide, carry_1) = wide.overflowing_add(wide);
    let carries = (add as u128)
        .wrapping_add(carry_lo as u128)
        .wrapping_add((carry_hi as u128) << 64);
    let (wide, carry_2) = wide.overflowing_add(carries);
    (wide as u64, (wide >> 64) as u64, carry_1 | carry_2)
}

// Helper while [Rust#85532](https://github.com/rust-lang/rust/issues/85532) stabilizes.
#[inline]
#[must_use]
const fn borrowing_sub(lhs: u64, rhs: u64, borrow: bool) -> (u64, bool) {
    let (result, borrow_1) = lhs.overflowing_sub(rhs);
    let (result, borrow_2) = result.overflowing_sub(borrow as u64);
    (result, borrow_1 | borrow_2)
}
