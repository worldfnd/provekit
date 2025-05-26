use {
    crate::{noir_to_r1cs::NoirToR1CSCompiler, r1cs_solver::WitnessBuilder, FieldElement},
    ark_ff::{BigInteger, One, PrimeField, Zero},
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

impl DigitalDecompositionWitnesses {
    pub fn new(
        next_witness_idx: usize,
        log_bases: Vec<usize>,
        witnesses_to_decompose: Vec<usize>,
    ) -> Self {
        let num_witnesses_to_decompose = witnesses_to_decompose.len();
        let digital_decomp_length = log_bases.len();
        Self {
            log_bases,
            num_witnesses_to_decompose,
            witnesses_to_decompose,
            first_witness_idx: next_witness_idx,
            num_witnesses: digital_decomp_length * num_witnesses_to_decompose,
        }
    }

    /// Returns the witness index of the `value_offset`-th witness of the
    /// `digit_place`-th digit. Note that `value_offset` is the index of the
    /// witness in the original list of witnesses (not itself a witness
    /// index).
    pub fn get_digit_witness_index(&self, digit_place: usize, value_offset: usize) -> usize {
        debug_assert!(digit_place < self.log_bases.len());
        debug_assert!(value_offset < self.num_witnesses_to_decompose);
        self.first_witness_idx + digit_place * self.num_witnesses_to_decompose + value_offset
    }

    /// Solve for the witness values allocated to the digital decomposition.
    pub fn solve(&self, witness: &mut [Option<FieldElement>]) {
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

/// Adds the witnesses and constraints for the digital decomposition of the
/// given witnesses in a mixed base decomposition (see
/// [DigitalDecompositionWitnesses]).  Does NOT add constraints for
/// range checking the digits - this is left to the caller (as sometimes these
/// range checks are obviated e.g. by later lookups, as in the case of the binop
/// codes).
pub(crate) fn add_digital_decomposition(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    log_bases: Vec<usize>,
    witnesses_to_decompose: Vec<usize>,
) -> DigitalDecompositionWitnesses {
    let next_witness_idx = r1cs_compiler.num_witnesses();
    let dd_struct = DigitalDecompositionWitnesses::new(
        next_witness_idx,
        log_bases.clone(),
        witnesses_to_decompose,
    );
    r1cs_compiler.add_witness_builder(WitnessBuilder::DigitalDecomposition(dd_struct.clone()));
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
            digit_multipliers
                .iter()
                .enumerate()
                .for_each(|(digit_place, digit_multiplier)| {
                    let digit_witness = dd_struct.get_digit_witness_index(digit_place, i);
                    recomp_summands.push((FieldElement::from(*digit_multiplier), digit_witness));
                });
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::one(), r1cs_compiler.witness_one())],
                &[(FieldElement::one(), *value)],
                &recomp_summands,
            );
        });
    dd_struct
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
