use {
    crate::SmolHasher, bytemuck::{cast, cast_ref, cast_slice_mut, checked::cast_mut}, hex_literal::hex, num_traits::WrappingMul, std::fmt::Display
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
    [0; 4]
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
}

fn mont_mul(a: U256, b: U256) -> U256 {
    let mut t = [0; 6];
    for i in 0..4 {
        // At the start of the loop t[5] is zero.

        // Compute partial product
        let mut carry = 0_u64;
        for j in 0..4 {
            let r =  (carry as u128) + (t[j] as u128) + (a[j] as u128) * (b[i] as u128);
            t[j] = r as u64;
            carry = (r >> 64) as u64;
        }
        // Propagate last carry.
        {
            let r =  (carry as u128) + (t[4] as u128);
            t[4] = r as u64;
            t[5] = (r >> 64) as u64;
        }

        // Comput multiple of Modulus to add that will clear t[0]
        let m = t[0].wrapping_mul(INV);

        // Add m times Modulus
        let mut carry = 0_u64;
        for j in 0..4 {
            let r =  (carry as u128) + (t[j] as u128) + (MODULUS[j] as u128) * (m as u128);
            t[j] = r as u64;
            carry = (r >> 64) as u64;
        }
        // Propagate last carry.
        {
            let r =  (carry as u128) + (t[4] as u128);
            t[4] = r as u64;
            t[5] = (r >> 64) as u64;
        }
        debug_assert_eq!(t[0], 0);

        // Shift t to the right by 64 bits.
        for j in 0..5 {
            t[j] = t[j + 1];
        }
        t[5] = 0;
    }
}

fn adc(a: u64, b: u64, c: u64) -> (u64, u64) {
    let r = (a as u128) + (b as u128) + (c as u128);
    (r as u64, (r >> 64) as u64)
}

fn addc(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let r = (a as u128) + (b as u128) + (c as u128) + (d as u128));
    (r as u64, (r >> 64) as u64)
}

// (r, c') = a + b * c
fn mac(a: u64, b: u64, c: &mut u64) -> u64 {
    let r = (a as u128) + (b as u128) * (*c as u128);
    *c = (r >> 64) as u64;
    r as u64
}

fn double(lo: u64, hi: u64) -> (u64, u64, u64) {
    (lo << 1, (hi << 1) | (lo >> 63), hi >> 63)
}
