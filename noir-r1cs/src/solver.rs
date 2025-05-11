use acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    };
use rand::Rng;

use crate::compiler::{DigitalDecompositionWitnesses, SpiceMemoryOperation, SpiceWitnesses};

#[derive(Debug, Clone)]
/// Indicates how to solve for an R1CS witness value in terms of earlier R1CS witness values and/or
/// ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    /// (witness index, constant value)
    Constant(usize, FieldElement),
    /// A witness value carried over from the ACIR circuit (at the specified ACIR witness index)
    /// (includes ACIR inputs and outputs)
    /// (witness index, ACIR witness index)
    Acir(usize, usize),
    /// A Fiat-Shamir challenge value
    /// (witness index)
    Challenge(usize),
    /// The inverse of the value at a specified witness index
    /// (witness index, operand witness index)
    Inverse(usize, usize),
    /// The sum of many witness values
    /// (witness index, vector of operand witness indices)
    Sum(usize, Vec<usize>),
    /// The product of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    Product(usize, usize, usize),
    /// The difference of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    /// This is used in interfacing the RAM checking code with the range checking code.
    Difference(usize, usize, usize),
    /// Solves for the number of times that each memory address occurs in read-only memory.
    /// Arguments: (first witness index, range size, vector of all witness indices for values purported to be in the range)
    MultiplicitiesForRange(usize, usize, Vec<usize>),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index), rs_challenge, value).
    IndexedLogUpDenominator(usize, usize, (FieldElement, usize), usize, usize),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (witness index, sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, usize, (FieldElement, usize)),
    /// Products with linear operations on the witness indices.
    /// Fields are ProductLinearOperation(witness_idx, (index, a, b), (index, c, d)) such that
    /// we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(
        usize,
        (usize, FieldElement, FieldElement),
        (usize, FieldElement, FieldElement),
    ),
    /// A factor of the multiset check used in read/write memory checking.
    /// Values: (witness index, sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness))
    /// where sz_challenge, rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes:
    /// sz_challenge - (addr * addr_witness + rs_challenge * value + rs_challenge * rs_challenge * timer * timer_witness)
    MemOpMultisetFactor(usize, usize, usize, (FieldElement, usize), usize, (FieldElement, usize)),
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR solver.)
    SpiceWitnesses(SpiceWitnesses),

    //FIXME
    DigitalDecomposition(DigitalDecompositionWitnesses),
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness vector.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::Constant(_, _) => 1,
            WitnessBuilder::Acir(_, _) => 1,
            WitnessBuilder::Challenge(_) => 1,
            WitnessBuilder::Inverse(_, _) => 1,
            WitnessBuilder::Sum(_, _) => 1,
            WitnessBuilder::Product(_, _, _) => 1,
            WitnessBuilder::Difference(_, _, _) => 1,
            WitnessBuilder::MultiplicitiesForRange(_, range_size, _) => *range_size,
            WitnessBuilder::IndexedLogUpDenominator(_, _, _, _, _) => 1,
            WitnessBuilder::LogUpDenominator(_, _, _) => 1,
            WitnessBuilder::ProductLinearOperation(_, _, _) => 1,
            WitnessBuilder::MemOpMultisetFactor(_, _, _, _, _, _) => 1,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => spice_witnesses_struct.num_witnesses,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.num_witnesses,
        }
    }

    /// Return the index of the first witness value that this builder writes to.
    pub fn first_witness_idx(&self) -> usize {
        match self {
            WitnessBuilder::Constant(start_idx, _) => *start_idx,
            WitnessBuilder::Acir(start_idx, _) => *start_idx,
            WitnessBuilder::Challenge(start_idx) => *start_idx,
            WitnessBuilder::Inverse(start_idx, _) => *start_idx,
            WitnessBuilder::Sum(start_idx, _) => *start_idx,
            WitnessBuilder::Product(start_idx, _, _) => *start_idx,
            WitnessBuilder::Difference(start_idx, _, _) => *start_idx,
            WitnessBuilder::MultiplicitiesForRange(start_idx, _, _) => *start_idx,
            WitnessBuilder::IndexedLogUpDenominator(start_idx, _, _, _, _) => *start_idx,
            WitnessBuilder::LogUpDenominator(start_idx, _, _) => *start_idx,
            WitnessBuilder::ProductLinearOperation(start_idx, _, _) => *start_idx,
            WitnessBuilder::MemOpMultisetFactor(start_idx, _, _, _, _, _) => *start_idx,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => spice_witnesses_struct.first_witness_idx,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.first_witness_idx,
        }
    }

    /// As per solve(), but additionally appends the solved witness values to the transcript.
    pub fn solve_and_append_to_transcript(
        &self,
        witness: &mut [FieldElement],
        acir_witnesses: &WitnessMap<FieldElement>,
        transcript: &mut MockTranscript,
    ) {
        self.solve(witness, acir_witnesses, transcript);
        for i in 0..self.num_witnesses() {
            transcript.append(witness[self.first_witness_idx() + i]);
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes them to the witness vector.
    pub fn solve(&self, witness: &mut [FieldElement], acir_witnesses: &WitnessMap<FieldElement>, transcript: &mut MockTranscript) {
        match self {
            WitnessBuilder::Constant(witness_idx, c) => {
                witness[*witness_idx] = *c;
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = acir_witnesses[&AcirWitness(*acir_witness_idx as u32)];
            }
            WitnessBuilder::Challenge(witness_idx) => {
                witness[*witness_idx] = transcript.draw_challenge();
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand: FieldElement = witness[*operand_idx];
                witness[*witness_idx] = operand.inverse();
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = operands
                    .iter()
                    .map(|idx| witness[*idx])
                    .fold(FieldElement::zero(), |acc, x| acc + x);
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a];
                let b: FieldElement = witness[*operand_idx_b];
                witness[*witness_idx] = a * b;
            }
            WitnessBuilder::Difference(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a];
                let b: FieldElement = witness[*operand_idx_b];
                witness[*witness_idx] = a - b;
            }
            WitnessBuilder::IndexedLogUpDenominator(witness_idx, sz_challenge, (index_coeff, index), rs_challenge, value) => {
                let index = witness[*index];
                let value = witness[*value];
                let rs_challenge = witness[*rs_challenge];
                let sz_challenge = witness[*sz_challenge];
                witness[*witness_idx] = sz_challenge - (*index_coeff * index + rs_challenge * value);
            }
            WitnessBuilder::LogUpDenominator(witness_idx, sz_challenge, (value_coeff, value)) => {
                witness[*witness_idx] = witness[*sz_challenge] - (*value_coeff * witness[*value]);
            }
            WitnessBuilder::ProductLinearOperation(witness_idx, (x, a, b), (y, c, d)) => {
                witness[*witness_idx] = (*a * witness[*x] + *b) * (*c * witness[*y] + *d);
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    let value = witness[*value_witness_idx].try_to_u64().unwrap() as usize;
                    multiplicities[value] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = FieldElement::from(*count);
                }
            }
            WitnessBuilder::MemOpMultisetFactor(witness_idx, sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness)) => {
                witness[*witness_idx] = witness[*sz_challenge] - (*addr * witness[*addr_witness]
                    + witness[*rs_challenge] * witness[*value]
                    + witness[*rs_challenge] * witness[*rs_challenge] * *timer * witness[*timer_witness]);
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                let mut rv_final = witness[spice_witnesses.initial_values_start..spice_witnesses.initial_values_start + spice_witnesses.memory_length].to_vec();
                let mut rt_final = vec![0; spice_witnesses.memory_length];
                for (mem_op_index, mem_op) in spice_witnesses.memory_operations.iter().enumerate() {
                    match mem_op {
                        SpiceMemoryOperation::Load(addr, value, read_timestamp) => {
                            let addr = witness[*addr];
                            let addr_as_usize = addr.try_to_u64().unwrap() as usize;
                            witness[*read_timestamp] = FieldElement::from(rt_final[addr_as_usize]);
                            rv_final[addr_as_usize] = witness[*value];
                            rt_final[addr_as_usize] = mem_op_index + 1;
                        }
                        SpiceMemoryOperation::Store(addr, old_value, new_value, read_timestamp) => {
                            let addr = witness[*addr];
                            let addr_as_usize = addr.try_to_u64().unwrap() as usize;
                            witness[*old_value] = rv_final[addr_as_usize];
                            witness[*read_timestamp] = FieldElement::from(rt_final[addr_as_usize]);
                            let new_value = witness[*new_value];
                            rv_final[addr_as_usize] = new_value;
                            rt_final[addr_as_usize] = mem_op_index + 1;
                        }
                    }

                }
                // Copy the final values and read timestamps into the witness vector
                for i in 0..spice_witnesses.memory_length {
                    witness[spice_witnesses.rv_final_start + i] = rv_final[i];
                    witness[spice_witnesses.rt_final_start + i] = FieldElement::from(rt_final[i]);
                }
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.values.iter().enumerate().for_each(|(i, value_witness_idx)| {
                    let value = witness[*value_witness_idx];
                    let value_bits = field_to_le_bits(value);
                    // Grab the bits of the element that we need for each digit, and turn them back into field elements.
                    let mut start_bit = 0;
                    for (digit_idx, digit_start_idx) in dd_struct.digit_start_indices.iter().enumerate() {
                        let log_base = dd_struct.log_bases[digit_idx];
                        let digit_bits = &value_bits[start_bit..start_bit + log_base];
                        let digit_value = le_bits_to_field(digit_bits);
                        witness[*digit_start_idx + i] = digit_value;
                        start_bit += log_base;
                    }
                });
            }
        }
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
    padded_bits_le[..padding_amt].copy_from_slice(bits);
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
fn test_le_bits_to_field() {
    let bits = vec![true, false, true, false, false];
    let value = le_bits_to_field(&bits);
    assert_eq!(value.try_to_u32().unwrap(), 5);
}

/// Mock transcript. To be replaced.
pub struct MockTranscript { }

impl MockTranscript {
    pub fn new() -> Self {
        Self {}
    }

    pub fn append(&mut self, _value: FieldElement) {}

    pub fn draw_challenge(&mut self) -> FieldElement {
        let mut rng = rand::thread_rng();
        let n: u32 = rng.gen();
        n.into()
    }
}
