use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
};

/// Trait for byte-based hash functions (SHA2, SHA3, BLAKE3).
pub trait ByteHasher: Clone + Send + Sync + 'static {
    fn hash(data: &[u8]) -> [u8; 32];
}

/// Compress two field elements using a byte-based hash (Feistel structure).
#[inline]
pub fn byte_hash_compress<H: ByteHasher>(l: FieldElement, r: FieldElement) -> FieldElement {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&field_to_bytes(l));
    data[32..].copy_from_slice(&field_to_bytes(r));
    bytes_to_field(H::hash(&data))
}

/// Feistel permutation for byte-based hashes.
#[inline]
pub fn byte_hash_permute<H: ByteHasher>(
    l: FieldElement,
    r: FieldElement,
) -> (FieldElement, FieldElement) {
    (r, byte_hash_compress::<H>(l, r))
}

/// Brute-force PoW solver for byte-based hashes.
pub fn byte_hash_solve_pow<H: ByteHasher>(challenge: [u8; 32], bits: f64) -> Option<u64> {
    for nonce in 0..u64::MAX {
        if byte_hash_check_pow::<H>(challenge, bits, nonce) {
            return Some(nonce);
        }
    }
    None
}

/// PoW verification for byte-based hashes.
#[inline]
pub fn byte_hash_check_pow<H: ByteHasher>(challenge: [u8; 32], bits: f64, nonce: u64) -> bool {
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(&challenge);
    data[32..].copy_from_slice(&nonce.to_le_bytes());
    check_pow_difficulty(&H::hash(&data), bits)
}

#[inline]
pub fn field_to_bytes(f: FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let limbs = f.into_bigint().0;
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

#[inline]
pub fn bytes_to_field(bytes: [u8; 32]) -> FieldElement {
    let limbs: [u64; 4] = [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ];
    FieldElement::from(BigInt::new(limbs))
}

#[inline]
pub fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

#[inline]
pub fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[inline]
pub fn check_pow_difficulty(hash: &[u8; 32], bits: f64) -> bool {
    count_leading_zeros(hash) as f64 >= bits
}
