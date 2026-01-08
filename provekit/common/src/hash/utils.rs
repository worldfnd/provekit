use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
};

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
