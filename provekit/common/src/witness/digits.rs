use {
    crate::FieldElement,
    ark_ff::{BigInt, BitIteratorLE, PrimeField},
    itertools::Itertools,
    serde::{Deserialize, Serialize},
};

/// Allocates witnesses for the digital decomposition of the given witnesses
/// into its digits in the given bases.  A log base is specified for each digit
/// (permitting mixed base decompositions). The order of bases is little-endian.
/// Witnesses are grouped by digital place, in the order of the bases,
/// where each group of witnesses is in 1:1 correspondence with
/// witnesses_to_decompose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DigitalDecompositionWitnesses {
    /// The log base of each digit (in little-endian order)
    pub log_bases:                  Vec<usize>,
    /// The number of witnesses to decompose
    pub num_witnesses_to_decompose: usize,
    /// Witness indices of the values to be decomposed
    pub witnesses_to_decompose:     Vec<usize>,
    /// The index of the first witness written to
    pub first_witness_idx:          usize,
    /// The number of witnesses written to
    pub num_witnesses:              usize,
}

/// Compute a mixed-base decomposition of a field element into its digits, using
/// the given log bases. Decomposition is little-endian.
/// Panics if the value provided can not be represented in the given bases.
// TODO: with stronger constraints on log_bases will allow us to remove the
// remaining allocation
pub fn decompose_into_digits(value: FieldElement, log_bases: &[usize]) -> Vec<FieldElement> {
    let num_digits = log_bases.len();
    let mut digits = Vec::with_capacity(num_digits);
    let mut value_bits = field_to_le_bits(value);
    let ref_value_bits = &mut value_bits;
    // Grab the bits of the element that we need for each digit, and turn them back
    // into field elements.
    for &log_base in log_bases {
        let digit_bits = ref_value_bits.take(log_base);
        digits.push(le_bits_to_field(digit_bits))
    }

    let mut remaining_bits = value_bits;
    assert!(
        remaining_bits.all(|bit| !bit),
        "Higher order bits are not zero"
    );
    digits
}

/// Decomposes a field element into its bits, in little-endian order.
fn field_to_le_bits(value: FieldElement) -> BitIteratorLE<BigInt<4>> {
    BitIteratorLE::new(value.into_bigint())
}

/// Given the binary representation of a field element in little-endian order,
/// convert it to a field element. The input is padded to the next multiple of 8
/// bits.
///
/// # Note
/// Only the first 32 bytes (256 bits) of the input will be used. Any additional
/// bits will be ignored.
fn le_bits_to_field<I>(bits: I) -> FieldElement
where
    I: Iterator<Item = bool>,
{
    const LEN: usize = size_of::<<FieldElement as PrimeField>::BigInt>();
    let mut le_bytes = [0; LEN];
    for (i, chunk_in_bits) in bits.chunks(8).into_iter().take(LEN).enumerate() {
        le_bytes[i] = chunk_in_bits
            .into_iter()
            .enumerate()
            .fold(0u8, |acc, (i, bit)| acc | ((bit as u8) << i))
    }
    FieldElement::from_le_bytes_mod_order(&le_bytes)
}

#[cfg(test)]
#[test]
fn test_decompose_into_digits() {
    let value = FieldElement::from(3 + 2u32 * 256 + 256 * 256);
    let log_bases = vec![8, 8, 4];
    let digits = decompose_into_digits(value, &log_bases);
    assert_eq!(digits.len(), log_bases.len());
    assert_eq!(digits[0], FieldElement::from(3u32));
    assert_eq!(digits[1], FieldElement::from(2u32));
    assert_eq!(digits[2], FieldElement::from(1u32));
}

#[cfg(test)]
#[test]
// Changing from FieldElement :: from_be to from_le didn't negate this test. So
// this needs to be extended
fn test_field_to_le_bits() {
    let value = FieldElement::from(5u32);
    let bits: Vec<bool> = field_to_le_bits(value).collect();
    assert_eq!(bits.len(), 256);
    assert!(bits[0]);
    assert!(!bits[1]);
    assert!(bits[2]);
    assert!(!bits[254]);
    assert!(!bits[255]);
}

#[cfg(test)]
#[test]
fn test_le_bits_to_field() {
    let bits = vec![true, false, true, false, false];
    let value = le_bits_to_field(bits.into_iter().take(64));
    assert_eq!(value.into_bigint().0[0], 5);
}
