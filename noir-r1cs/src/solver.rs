use acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
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
    /// Solves for the number of times that each memory address occurs.
    /// Arguments: (memory size, vector of all address witness indices)
    MemoryAccessCounts(usize, Vec<usize>),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (sz_challenge, (index_coeff, index), rs_challenge, value).
    LogUpDenominator(usize, (FieldElement, usize), usize, usize),
}

impl WitnessBuilder {
    /// The number of witness values that this builder will produce.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::Constant(_) => 1,
            WitnessBuilder::Acir(_) => 1,
            WitnessBuilder::Challenge => 1,
            WitnessBuilder::Inverse(_) => 1,
            WitnessBuilder::Sum(_) => 1,
            WitnessBuilder::Product(_, _) => 1,
            WitnessBuilder::MemoryAccessCounts(memory_size, _) => *memory_size,
            WitnessBuilder::LogUpDenominator(_, _, _, _) => 1,
        }
    }

    pub fn solve_and_append_to_transcript(
        &self,
        start_idx: usize,
        witness: &mut [FieldElement],
        acir_witnesses: &WitnessMap<FieldElement>,
        transcript: &mut MockTranscript,
    ) {
        let num_witnesses = self.num_witnesses();
        self.solve(start_idx, witness, acir_witnesses, transcript);
        for i in 0..num_witnesses {
            transcript.append(witness[start_idx + i]);
        }
    }

    pub fn solve(&self, start_idx: usize, witness: &mut [FieldElement], acir_witnesses: &WitnessMap<FieldElement>, transcript: &mut MockTranscript) {
        match self {
            WitnessBuilder::Constant(c) => {
                witness[start_idx] = *c;
            }
            WitnessBuilder::Acir(acir_witness_idx) => {
                witness[start_idx] = acir_witnesses[&AcirWitness(*acir_witness_idx as u32)];
            }
            WitnessBuilder::Challenge => {
                witness[start_idx] = transcript.draw_challenge();
            }
            WitnessBuilder::Inverse(operand_idx) => {
                let operand: FieldElement = witness[*operand_idx];
                witness[start_idx] = operand.inverse();
            }
            WitnessBuilder::Sum(operands) => {
                witness[start_idx] = operands
                    .iter()
                    .map(|idx| witness[*idx])
                    .fold(FieldElement::zero(), |acc, x| acc + x);
            }
            WitnessBuilder::Product(operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a];
                let b: FieldElement = witness[*operand_idx_b];
                witness[start_idx] = a * b;
            }
            WitnessBuilder::LogUpDenominator(sz_challenge, (index_coeff, index), rs_challenge, value) => {
                let index = witness[*index];
                let value = witness[*value];
                let rs_challenge = witness[*rs_challenge];
                let sz_challenge = witness[*sz_challenge];
                witness[start_idx] = sz_challenge - (*index_coeff * index + rs_challenge * value);
            }
            WitnessBuilder::MemoryAccessCounts(memory_size, address_witnesses) => {
                let mut memory_read_counts = vec![0u32; *memory_size];
                for addr_witness_idx in address_witnesses {
                    let addr = witness[*addr_witness_idx].try_to_u64().unwrap() as usize;
                    memory_read_counts[addr] += 1;
                }
                for (i, count) in memory_read_counts.iter().enumerate() {
                    witness[start_idx + i] = FieldElement::from(*count);
                }
            }
        }
    }
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

    /// Equal to the sum of the lengths of the witness builders + 1 (for the constant one witness)
    pub next_witness_idx: usize,
}

impl R1CSSolver {
    pub fn new() -> Self {
        Self {
            witness_builders: vec![WitnessBuilder::Constant(FieldElement::one())],
            next_witness_idx: 1,
        }
    }

    /// Add a new witness to the R1CS solver.
    pub fn add_witness_builder(&mut self, witness_builder: WitnessBuilder) {
        self.next_witness_idx += witness_builder.num_witnesses();
        self.witness_builders.push(witness_builder);
    }

    /// Given the ACIR witness values, solve for the R1CS witness values.
    pub fn solve(
        &self,
        transcript: &mut MockTranscript,
        acir_witnesses: &WitnessMap<FieldElement>,
    ) -> Vec<FieldElement> {
        let mut witness = vec![FieldElement::zero(); self.num_witnesses()];
        let mut witness_idx = 0;
        self.witness_builders
            .iter()
            .for_each(|witness_builder| {
                witness_builder.solve_and_append_to_transcript(
                    witness_idx,
                    &mut witness,
                    acir_witnesses,
                    transcript,
                );
                witness_idx += witness_builder.num_witnesses();
            });
        witness
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        self.next_witness_idx
    }

    /// Index of the constant 1 witness
    pub const fn witness_one(&self) -> usize {
        0
    }
}
