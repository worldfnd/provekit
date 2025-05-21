use {
    crate::{compiler::R1CS, solver::WitnessBuilder},
    acir::{AcirField, FieldElement},
};

/// Allocates witnesses for the digital decomposition of the given witnesses
/// into its digits in the given bases.  A log base is specified for each digit
/// (permitting mixed base decompositions). The order of bases is little-endian.
/// Witnesses for the digits of each value are allocated contiguously, starting
/// from first_witness_idx, in the order of the bases.
#[derive(Debug, Clone)]
pub(crate) struct DigitalDecompositionWitnesses {
    /// The log base of each digit (in little-endian order)
    pub log_bases:              Vec<usize>,
    /// Witness indices of the values to be decomposed
    pub witnesses_to_decompose: Vec<usize>,
    // TODO(Ben) this is redundant, really, since each value has a fixed number of digits and the
    // witnesses are stored contiguously
    /// Witness indices for the digits of the decomposition of each value
    /// (indexed by digital place).
    pub digit_start_indices:    Vec<usize>,
    /// The index of the first witness written to
    pub first_witness_idx:      usize,
    /// The number of witnesses written to
    pub num_witnesses:          usize,
}

impl DigitalDecompositionWitnesses {
    pub fn new(
        next_witness_idx: usize,
        log_bases: Vec<usize>,
        witnesses_to_decompose: Vec<usize>,
    ) -> Self {
        let num_values = witnesses_to_decompose.len();
        let digital_decomp_length = log_bases.len();
        let digit_start_indices = (0..digital_decomp_length)
            .map(|i| next_witness_idx + i * num_values)
            .collect::<Vec<_>>();
        Self {
            log_bases,
            witnesses_to_decompose,
            digit_start_indices,
            first_witness_idx: next_witness_idx,
            num_witnesses: digital_decomp_length * num_values,
        }
    }

    /// Solve for the witness values allocated to the digital decomposition.
    pub fn solve(&self, witness: &mut [FieldElement]) {
        self.witnesses_to_decompose
            .iter()
            .enumerate()
            .for_each(|(i, value_witness_idx)| {
                let value = witness[*value_witness_idx];
                let value_bits = field_to_le_bits(value);
                // Grab the bits of the element that we need for each digit, and turn them back
                // into field elements.
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

    /// Returns a vector of tuples, where each tuple contains the log base and
    /// the witness indices of the digits for that base (these may be used
    /// to range check the digits, for instance).
    pub fn digit_ranges(&self) -> Vec<(u32, Vec<usize>)> {
        let num_witnesses_to_decompose = self.witnesses_to_decompose.len();
        self.log_bases
            .iter()
            .map(|log_base| *log_base as u32)
            .zip(self.digit_start_indices.iter().map(|digit_start_index| {
                (0..num_witnesses_to_decompose)
                    .map(|i| *digit_start_index + i)
                    .collect::<Vec<_>>()
            }))
            .collect()
    }
}

/// Adds the witnesses and constraints for the digital decomposition of the
/// given witnesses in a mixed base decomposition (see
/// [DigitalDecompositionWitnesses]).  Does NOT add constraints for
/// range checking the digits - this is left to the caller (as sometimes these
/// range checks are obviated e.g. by later lookups, as in the case of the bin
/// op codes).
pub(crate) fn add_digital_decomposition(
    r1cs: &mut R1CS,
    log_bases: Vec<usize>,
    witnesses_to_decompose: Vec<usize>,
) -> DigitalDecompositionWitnesses {
    let next_witness_idx = r1cs.num_witnesses();
    let dd_struct = DigitalDecompositionWitnesses::new(
        next_witness_idx,
        log_bases.clone(),
        witnesses_to_decompose,
    );
    r1cs.add_witness_builder(WitnessBuilder::DigitalDecomposition(dd_struct.clone()));
    // Add the constraints for the digital recomposition
    let mut digit_multipliers = vec![FieldElement::one()];
    for log_base in log_bases[..log_bases.len() - 1].iter() {
        let multiplier = *digit_multipliers.last().unwrap() * FieldElement::from(1u64 << *log_base);
        digit_multipliers.push(multiplier);
    }
    dd_struct
        .witnesses_to_decompose
        .iter()
        .enumerate()
        .for_each(|(i, value)| {
            let mut recomp_summands = vec![];
            dd_struct
                .digit_start_indices
                .iter()
                .zip(digit_multipliers.iter())
                .for_each(|(digit_start_index, digit_multiplier)| {
                    let digit_witness = *digit_start_index + i;
                    recomp_summands.push((FieldElement::from(*digit_multiplier), digit_witness));
                });
            r1cs.matrices.add_constraint(
                &[(FieldElement::one(), r1cs.witness_one())],
                &[(FieldElement::one(), *value)],
                &recomp_summands,
            );
        });
    dd_struct
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
