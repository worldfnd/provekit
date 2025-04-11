use crate::compiler::BASE_DECOMPOSITION;
use {
    acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    },
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
    /// Witness builder to solve for the ith digit of the jth witness index in BASE [BASE_DECOMPOSITION],
    /// where 0 is the least significant digit. Fields are (i, j).
    DigitDecomp(u32, usize),
    /// The multiplicity of the ith digit, for a range check of j num_bits.
    /// Fields are (i, j).
    DigitMultiplicity(u32, u32),
}

/// Mock transcript. To be replaced.
pub struct MockTranscript {
    count: u32,
}

impl MockTranscript {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    pub fn append(&mut self, _value: FieldElement) {
        self.count += 1;
    }

    pub fn draw_challenge(&mut self) -> FieldElement {
        self.count += 1;
        self.count.into()
    }
}

pub struct R1CSSolver {
    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    /// The length of each memory block
    pub memory_lengths: BTreeMap<usize, usize>,

    /// The ranges that are checked.
    pub range_checks: Vec<u32>,
}

impl R1CSSolver {
    pub fn new() -> Self {
        Self {
            witness_builders: vec![WitnessBuilder::Constant(FieldElement::one())],
            memory_lengths: BTreeMap::new(),
            range_checks: Vec::new(),
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
        let mut digit_multiplicity_count: BTreeMap<u32, Vec<u32>> = self
            .range_checks
            .iter()
            .map(|range_check_bits| (*range_check_bits, vec![0u32; 1 << *range_check_bits]))
            .collect();

        self.witness_builders
            .iter()
            .enumerate()
            .for_each(|(witness_idx, witness_builder)| {
                assert_eq!(
                    witness[witness_idx], None,
                    "Witness {witness_idx} already set."
                );
                let value = match witness_builder {
                    WitnessBuilder::Constant(c) => *c,
                    WitnessBuilder::Acir(acir_witness_idx) => {
                        acir_witnesses[&AcirWitness(*acir_witness_idx as u32)]
                    }
                    WitnessBuilder::MemoryRead(
                        block_id,
                        addr_witness_idx,
                        value_acir_witness_idx,
                    ) => {
                        let addr =
                            witness[*addr_witness_idx].unwrap().try_to_u64().unwrap() as usize;
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
                    WitnessBuilder::DigitDecomp(i, j) => {
                        let witness_element_bytes: Vec<u8> = witness[*j].unwrap().to_be_bytes();
                        let num_bytes_in_digit = BASE_DECOMPOSITION / 8;
                        let index_bytes = &witness_element_bytes[((witness_element_bytes.len()
                            - (i + 1) as usize)
                            * num_bytes_in_digit as usize)
                            ..((witness_element_bytes.len() - *i as usize)
                                * num_bytes_in_digit as usize)];
                        let mut padded_bytes_for_usize = [0u8; std::mem::size_of::<usize>()];
                        assert!(index_bytes.len() < padded_bytes_for_usize.len());
                        let offset = padded_bytes_for_usize.len() - index_bytes.len();
                        padded_bytes_for_usize[offset..].copy_from_slice(&index_bytes);
                        let digit_usize = usize::from_be_bytes(padded_bytes_for_usize);
                        let digit = FieldElement::from_be_bytes_reduce(index_bytes);
                        digit_multiplicity_count
                            .get_mut(&BASE_DECOMPOSITION)
                            .unwrap()[digit_usize] += 1;
                        digit
                    }
                    WitnessBuilder::DigitMultiplicity(i, j) => {
                        // NOTE: all the digital decompositions must be added to the witness before querying
                        // the solver for the multiplicity.
                        let multiplicity = digit_multiplicity_count.get(j).unwrap()[*i as usize];
                        FieldElement::from(multiplicity)
                    }
                };
                witness[witness_idx] = Some(value);
                transcript.append(value);
            });

        witness.iter().map(|v| v.unwrap()).collect()
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        self.witness_builders.len()
    }

    /// Index of the constant 1 witness
    pub const fn witness_one(&self) -> usize {
        0
    }
}
