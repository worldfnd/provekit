use std::collections::HashMap;

use crate::utils::helpers::{
    compute_compact_bin_op_logup_repr, BinOp, LHS_SHIFT_FACTOR, OUTPUT_SHIFT_FACTOR,
    RHS_SHIFT_FACTOR,
};
use {
    crate::compiler::NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP,
    acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    },
    rand::Rng,
    std::collections::BTreeMap,
};

#[derive(Debug, Clone)]
/// Indicates how to solve for an R1CS witness value in terms of earlier R1CS witness values and/or
/// ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    Constant(FieldElement),
    /// A witness value carried over from the ACIR circuit (at the specified ACIR witness index)
    /// (includes ACIR inputs and outputs)
    Acir(usize),
    /// A Fiat-Shamir challenge value
    Challenge,
    /// The inverse of the value at a specified witness index
    Inverse(usize),
    /// The sum of many witness values
    Sum(Vec<usize>),
    /// The product of the values at two specified witness indices
    Product(usize, usize),
    /// Witness is the result of a memory read from the .0th block at the address determined by the .1th R1CS witness, whose value is available as the .2th acir witness index
    MemoryRead(usize, usize, usize),
    /// The number of times that the .1th index of the .0th memory block is accessed
    MemoryAccessCount(usize, usize),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (sz_challenge, (index_coeff, index), rs_challenge, value).
    IndexedLogUpDenominator(usize, (FieldElement, usize), usize, usize),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, (FieldElement, usize)),
    /// Products with linear operations on the witness indices.
    /// Fields are Product((index, a, b), (index, c, d)) such that
    /// we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(
        (usize, FieldElement, FieldElement),
        (usize, FieldElement, FieldElement),
    ),
    /// Witness builder to solve for the the digit of the ith witness index in BASE log(k),
    /// but for mixed-digit decompositions such that the previous digits in total took up $j$ bits.
    /// Fields are (log(k), i, j).
    DigitDecomp(u32, usize, u32),
    /// The multiplicity of the value i, for a range check of j num_bits.
    /// Fields are (i, j).
    DigitMultiplicity(u32, u32),
    /// NOTE: This is not going to add to the R1CS witness vector and is not actually
    /// a witness builder. It is simply a placeholder to indicate to the R1CS solver
    /// that we need to add to the multiplicity count of a particular witness.
    ///
    /// In particular, this is to add to the multiplicity count for the value of the
    /// jth witness in the lookup table for i bits. Fields are (i, j).
    AddMultiplicityCount(u32, usize),
    /// The multiplicity for the (lhs & rhs -> output) tuple, indexed by the
    /// "packed" version of the entry.
    AndOpcodeTupleMultiplicity(u32),
    /// The multiplicity for the (lhs ^ rhs -> output) tuple, indexed by the
    /// "packed" version of the entry.
    XorOpcodeTupleMultiplicity(u32),
    /// This generates the witnesses which are the "packed" version of inputs
    /// to binary functions (e.g. AND and XOR) which can be directly looked up
    /// in an appropriately packed lookup table.
    LookupTablePacking(usize, usize, usize, BinOp),
}

/// Mock transcript. To be replaced.
pub struct MockTranscript {}

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

pub struct R1CSSolver {
    /// Indicates how to solve for each R1CS witness
    ///
    pub witness_builders: Vec<WitnessBuilder>,

    /// The length of each memory block
    pub memory_lengths: BTreeMap<usize, usize>,
}

impl R1CSSolver {
    pub fn new() -> Self {
        Self {
            witness_builders: vec![WitnessBuilder::Constant(FieldElement::one())],
            memory_lengths: BTreeMap::new(),
        }
    }

    /// Add a new witness to the R1CS solver.
    pub fn add_witness_builder(&mut self, witness_builder: WitnessBuilder) {
        self.witness_builders.push(witness_builder);
    }

    /// Given the ACIR witness values, solve for the R1CS witness values.
    pub fn solve(
        &self,
        transcript: &mut MockTranscript,
        acir_witnesses: &WitnessMap<FieldElement>,
    ) -> Vec<FieldElement> {
        let mut witness: Vec<Option<FieldElement>> = vec![None; self.num_witnesses()];
        // The memory read counts for each block of memory
        let mut memory_read_counts: BTreeMap<usize, Vec<u32>> = self
            .memory_lengths
            .iter()
            .map(|(block_id, len)| (*block_id, vec![0u32; *len]))
            .collect();
        let mut multiplicity_counts: BTreeMap<u32, Vec<u32>> = (1
            ..=NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP)
            .map(|range_check_bits| (range_check_bits, vec![0u32; 1 << range_check_bits]))
            .collect();

        let mut witness_index = 0;

        // Multiplicities for the various AND and XOR table entries. Note that the
        // entries are stored in "compact" representation, although this is
        // not necessary.
        let mut and_table_count: HashMap<u32, u32> = (0..=255)
            .flat_map(|lhs| {
                (0..=255)
                    .map(move |rhs| (compute_compact_bin_op_logup_repr(lhs, rhs, BinOp::AND), 0))
            })
            .collect();
        let mut xor_table_count: HashMap<u32, u32> = (0..=255)
            .flat_map(|lhs| {
                (0..=255)
                    .map(move |rhs| (compute_compact_bin_op_logup_repr(lhs, rhs, BinOp::XOR), 0))
            })
            .collect();
        self.witness_builders.iter().for_each(|witness_builder| {
            assert_eq!(
                witness[witness_index], None,
                "Witness {witness_index} already set."
            );
            let value = match witness_builder {
                WitnessBuilder::Constant(c) => *c,
                WitnessBuilder::Acir(acir_witness_idx) => {
                    acir_witnesses[&AcirWitness(*acir_witness_idx as u32)]
                }
                WitnessBuilder::MemoryRead(block_id, addr_witness_idx, value_acir_witness_idx) => {
                    let addr = witness[*addr_witness_idx].unwrap().try_to_u64().unwrap() as usize;
                    memory_read_counts.get_mut(block_id).unwrap()[addr] += 1;
                    acir_witnesses[&AcirWitness(*value_acir_witness_idx as u32)]
                }
                WitnessBuilder::Challenge => transcript.draw_challenge(),
                WitnessBuilder::Inverse(operand_idx) => {
                    let operand: FieldElement = witness[*operand_idx].unwrap();
                    operand.inverse()
                }
                WitnessBuilder::Product(operand_idx_a, operand_idx_b) => {
                    let a: FieldElement = witness[*operand_idx_a].unwrap();
                    let b: FieldElement = witness[*operand_idx_b].unwrap();
                    a * b
                }
                WitnessBuilder::Sum(operands) => operands
                    .iter()
                    .map(|idx| witness[*idx].unwrap())
                    .fold(FieldElement::zero(), |acc, x| acc + x),
                WitnessBuilder::MemoryAccessCount(block_id, addr) => {
                    let count = memory_read_counts.get(block_id).unwrap()[*addr];
                    FieldElement::from(count)
                }
                WitnessBuilder::IndexedLogUpDenominator(
                    sz_challenge,
                    (index_coeff, index),
                    rs_challenge,
                    value,
                ) => {
                    let index = witness[*index].unwrap();
                    let value = witness[*value].unwrap();
                    let rs_challenge = witness[*rs_challenge].unwrap();
                    let sz_challenge = witness[*sz_challenge].unwrap();
                    sz_challenge - (*index_coeff * index + rs_challenge * value)
                }
                WitnessBuilder::LogUpDenominator(sz_challenge, (value_coeff, value)) => {
                    let sz_challenge = witness[*sz_challenge].unwrap();
                    let value = witness[*value].unwrap();
                    sz_challenge - (*value_coeff * value)
                }
                WitnessBuilder::ProductLinearOperation((x, a, b), (y, c, d)) => {
                    (*a * witness[*x].unwrap() + *b) * (*c * witness[*y].unwrap() + *d)
                }
                WitnessBuilder::DigitDecomp(log_k, i, previous_digit_sum) => {
                    let witness_element_bits: Vec<bool> = witness[*i]
                        .unwrap()
                        .to_be_bytes()
                        .iter()
                        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 != 0))
                        .collect();
                    // Grab the bits of the element that we need for the digit.
                    let index_bits = &witness_element_bits[(witness_element_bits.len()
                        - (*previous_digit_sum + log_k) as usize)
                        ..(witness_element_bits.len() - *previous_digit_sum as usize)];
                    // Convert the decomposed value back into a field element.
                    let next_multiple_of_8 = index_bits.len().div_ceil(8) * 8;
                    let padding_amt = next_multiple_of_8 - index_bits.len();
                    let mut padded_index_bits = vec![false; next_multiple_of_8];
                    padded_index_bits[padding_amt..].copy_from_slice(index_bits);
                    let be_byte_vec: Vec<u8> = padded_index_bits
                        .chunks(8)
                        .map(|chunk_in_bits| {
                            chunk_in_bits
                                .iter()
                                .enumerate()
                                .fold(0u8, |acc, (i, bit)| acc | ((*bit as u8) << (7 - i)))
                        })
                        .collect();
                    FieldElement::from_be_bytes_reduce(&be_byte_vec)
                }
                WitnessBuilder::DigitMultiplicity(i, j) => {
                    // NOTE: all the digital decompositions must be added to the witness before querying
                    // the solver for the multiplicity.
                    let multiplicity = multiplicity_counts.get(j).unwrap()[*i as usize];
                    FieldElement::from(multiplicity)
                }
                WitnessBuilder::AndOpcodeTupleMultiplicity(packed_val) => {
                    FieldElement::from(*and_table_count.get(packed_val).unwrap())
                }
                WitnessBuilder::LookupTablePacking(
                    lhs_r1cs_idx,
                    rhs_r1cs_idx,
                    output_r1cs_idx,
                    opcode_type,
                ) => {
                    // --- First we compute the actual value for the current packed witness ---
                    let lhs: FieldElement = witness[*lhs_r1cs_idx].unwrap();
                    let rhs: FieldElement = witness[*rhs_r1cs_idx].unwrap();
                    let output: FieldElement = witness[*output_r1cs_idx].unwrap();
                    let packed_output = lhs * FieldElement::from(LHS_SHIFT_FACTOR)
                        + rhs * FieldElement::from(RHS_SHIFT_FACTOR)
                        + output * FieldElement::from(OUTPUT_SHIFT_FACTOR);

                    // --- Then we add to the multiplicity count ---
                    let packed_output_u32 = packed_output.try_to_u32().unwrap();
                    match opcode_type {
                        BinOp::AND => {
                            let current_count =
                                and_table_count.get(&packed_output_u32).unwrap_or(&0);
                            and_table_count.insert(packed_output_u32, *current_count + 1);
                        }
                        BinOp::XOR => {
                            let current_count =
                                xor_table_count.get(&packed_output_u32).unwrap_or(&0);
                            xor_table_count.insert(packed_output_u32, *current_count + 1);
                        }
                    }

                    packed_output
                }
                WitnessBuilder::AddMultiplicityCount(i, j) => {
                    let witness_value = witness[*j].unwrap();
                    let witness_value_as_bytes = witness_value.to_be_bytes();
                    // Because we know that witnesses whose multiplicity we want will always
                    // be less than 16 bits, we can just extract the last two bytes.
                    assert!(NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP <= 16);
                    let significant_witness_bytes =
                        &witness_value_as_bytes[(witness_value_as_bytes.len() - 2)..];
                    let witness_as_usize =
                        u16::from_be_bytes(significant_witness_bytes.try_into().expect(
                            "Witness value should be representable as a u16 if being looked up",
                        )) as usize;
                    multiplicity_counts.get_mut(i).unwrap()[witness_as_usize] += 1;
                    // This does not matter as it does not add to the witnesses,
                    FieldElement::zero()
                }
                WitnessBuilder::XorOpcodeTupleMultiplicity(packed_val) => {
                    FieldElement::from(*xor_table_count.get(packed_val).unwrap())
                }
            };

            if let WitnessBuilder::AddMultiplicityCount(_, _) = *witness_builder {
            } else {
                witness[witness_index] = Some(value);
                transcript.append(value);
                witness_index += 1;
            }

            if witness_index == 1269894 {
                dbg!("bz");
                dbg!(&value);
            }
            if witness_index == 1269943 {
                dbg!("cz");
                dbg!(&value);
            }
        });

        witness.iter().map(|v| v.unwrap()).collect()
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        let mut num_witnesses = 0;
        self.witness_builders.iter().for_each(|wb| {
            if let WitnessBuilder::AddMultiplicityCount(_, _) = *wb {
            } else {
                num_witnesses += 1
            }
        });
        num_witnesses
    }

    /// Index of the constant 1 witness
    pub const fn witness_one(&self) -> usize {
        0
    }
}
