use acir::{AcirField, FieldElement};

/// Allocates witnesses for the digital decomposition of the given witnesses into its digits in the
/// given bases.  A log base is specified for each digit (permitting mixed base decompositions). The
/// order of bases is little-endian. The digits of each value appear contiguously, in the order of
/// the bases.
#[derive(Debug, Clone)]
pub(crate) struct DigitalDecompositionWitnesses {
    /// The log base of each digit (in little-endian order)
    pub log_bases: Vec<usize>,
    /// Witness indices of the values to be decomposed
    pub values: Vec<usize>,
    /// Witness indices for the digits of the decomposition of each value (indexed by digital place).
    pub digit_start_indices: Vec<usize>,
    /// The index of the first witness written to
    pub first_witness_idx: usize,
    /// The number of witnesses written to
    pub num_witnesses: usize,
}

impl DigitalDecompositionWitnesses {
    pub fn new(next_witness_idx: usize, log_bases: Vec<usize>, values: Vec<usize>) -> Self {
        let num_values = values.len();
        let digital_decomp_length = log_bases.len();
        let digit_start_indices = (0..digital_decomp_length)
            .map(|i| next_witness_idx + i * num_values).collect::<Vec<_>>();
        Self {
            log_bases,
            values,
            digit_start_indices,
            first_witness_idx: next_witness_idx,
            num_witnesses: digital_decomp_length * num_values,
        }
    }

    /// Solve for the witness values allocated to the digital decomposition.
    pub fn solve(&self, witness: &mut [FieldElement]) {
        self.values.iter().enumerate().for_each(|(i, value_witness_idx)| {
            let value = witness[*value_witness_idx];
            let value_bits = field_to_le_bits(value);
            // Grab the bits of the element that we need for each digit, and turn them back into field elements.
            let mut start_bit = 0;
            for (digit_idx, digit_start_idx) in self.digit_start_indices.iter().enumerate() {
                let log_base = self.log_bases[digit_idx];
                let digit_bits = &value_bits[start_bit..start_bit + log_base];
                let digit_value = le_bits_to_field(digit_bits);
                witness[*digit_start_idx + i] = digit_value;
                start_bit += log_base;
            }
        });
    }
}

/// Decomposes a field element into its bits, in little-endian order.
pub(crate) fn field_to_le_bits(value: FieldElement) -> Vec<bool> {
    value
        .to_be_bytes()
        .iter()
        .rev()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 != 0))
        .collect()
}

/// Given the binary representation of a field element in little-endian order, convert it to a field
/// element. The input is padded to the next multiple of 8 bits.
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
    FieldElement::from_be_bytes_reduce(&be_byte_vec)
}

#[cfg(test)]
#[test]
fn test_field_to_le_bits() {
    let value = FieldElement::from(5u32);
    let bits = field_to_le_bits(value);
    assert_eq!(bits.len(), 256);
    assert_eq!(bits[0], true);
    assert_eq!(bits[1], false);
    assert_eq!(bits[2], true);
    assert_eq!(bits[254], false);
    assert_eq!(bits[255], false);
}

#[cfg(test)]
#[test]
fn test_le_bits_to_field() {
    let bits = vec![true, false, true, false, false];
    let value = le_bits_to_field(&bits);
    assert_eq!(value.try_to_u32().unwrap(), 5);
}
