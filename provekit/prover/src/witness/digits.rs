use {
    ark_ff::{BigInteger, PrimeField},
    ark_std::Zero,
    provekit_common::{witness::DigitalDecompositionWitnesses, FieldElement},
};

pub(crate) trait DigitalDecompositionWitnessesSolver {
    fn solve(&self, witness: &mut [Option<FieldElement>]);
}

impl DigitalDecompositionWitnessesSolver for DigitalDecompositionWitnesses {
    fn solve(&self, witness: &mut [Option<FieldElement>]) {
        self.witnesses_to_decompose
            .iter()
            .enumerate()
            .for_each(|(i, value_witness_idx)| {
                let value = witness[*value_witness_idx].unwrap();
                let digits = decompose_into_digits(value, &self.log_bases);
                digits
                    .iter()
                    .enumerate()
                    .for_each(|(digit_place, digit_value)| {
                        witness[self.first_witness_idx
                            + digit_place * self.witnesses_to_decompose.len()
                            + i] = Some(*digit_value);
                    });
            });
    }
}

/// Compute a mixed-base decomposition of a field element into its digits, using
/// the given log bases. Decomposition is little-endian.
/// Panics if the value provided can not be represented in the given bases.
pub(crate) fn decompose_into_digits(value: FieldElement, log_bases: &[usize]) -> Vec<FieldElement> {
    let num_digits = log_bases.len();
    let mut digits = vec![FieldElement::zero(); num_digits];
    let value_bits = field_to_le_bits(value);
    // Grab the bits of the element that we need for each digit, and turn them back
    // into field elements.
    let mut start_bit = 0;
    for digit_idx in 0..num_digits {
        let log_base = log_bases[digit_idx];
        let digit_bits = &value_bits[start_bit..start_bit + log_base];
        let digit_value = le_bits_to_field(digit_bits);
        digits[digit_idx] = digit_value;
        start_bit += log_base;
    }
    let remaining_bits = &value_bits[start_bit..];
    assert!(
        remaining_bits.iter().all(|&bit| !bit),
        "Higher order bits are not zero"
    );
    digits
}

/// Decomposes a field element into its bits, in little-endian order.
pub(crate) fn field_to_le_bits(value: FieldElement) -> Vec<bool> {
    value.into_bigint().to_bits_le()
}

/// Given the binary representation of a field element in little-endian order,
/// convert it to a field element. The input is padded to the next multiple of 8
/// bits.
pub(crate) fn le_bits_to_field(bits: &[bool]) -> FieldElement {
    let next_multiple_of_8 = bits.len().div_ceil(8) * 8;
    let padding_amt = next_multiple_of_8 - bits.len();
    let mut padded_bits_le = vec![false; next_multiple_of_8];
    padded_bits_le[..(next_multiple_of_8 - padding_amt)].copy_from_slice(bits);
    let be_byte_vec: Vec<u8> = padded_bits_le
        .chunks(8)
        .map(|chunk_in_bits| {
            chunk_in_bits
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, bit)| acc | ((*bit as u8) << i))
        })
        .rev()
        .collect();
    FieldElement::from_be_bytes_mod_order(&be_byte_vec)
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
fn test_field_to_le_bits() {
    let value = FieldElement::from(5u32);
    let bits = field_to_le_bits(value);
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
    let value = le_bits_to_field(&bits);
    assert_eq!(value.into_bigint().0[0], 5);
}
