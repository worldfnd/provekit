use acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    };
use rand::Rng;

use crate::compiler::{SpiceMemoryOperation, SpiceWitnesses};

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
    /// Solves for the number of times that each memory address occurs in read-only memory.
    /// Arguments: (first witness index, memory size, vector of all address witness indices)
    MemoryAccessCounts(usize, usize, Vec<usize>),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index), rs_challenge, value).
    LogUpDenominator(usize, usize, (FieldElement, usize), usize, usize),
    /// A factor of the multiset check used in read/write memory checking.
    /// Values: (witness index, sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness))
    /// where sz_challenge, rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes:
    /// sz_challenge - (addr * addr_witness + rs_challenge * value + rs_challenge * rs_challenge * timer * timer_witness)
    MemOpMultisetFactor(usize, usize, usize, (FieldElement, usize), usize, (FieldElement, usize)),
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR solver.)
    SpiceWitnesses(SpiceWitnesses),
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
            WitnessBuilder::MemoryAccessCounts(_, memory_size, _) => *memory_size,
            WitnessBuilder::LogUpDenominator(_, _, _, _, _) => 1,
            WitnessBuilder::MemOpMultisetFactor(_, _, _, _, _, _) => 1,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => spice_witnesses_struct.num_witnesses,
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
            WitnessBuilder::MemoryAccessCounts(start_idx, _, _) => *start_idx,
            WitnessBuilder::LogUpDenominator(start_idx, _, _, _, _) => *start_idx,
            WitnessBuilder::MemOpMultisetFactor(start_idx, _, _, _, _, _) => *start_idx,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => spice_witnesses_struct.first_witness_idx,
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
            WitnessBuilder::LogUpDenominator(witness_idx, sz_challenge, (index_coeff, index), rs_challenge, value) => {
                let index = witness[*index];
                let value = witness[*value];
                let rs_challenge = witness[*rs_challenge];
                let sz_challenge = witness[*sz_challenge];
                witness[*witness_idx] = sz_challenge - (*index_coeff * index + rs_challenge * value);
            }
            WitnessBuilder::MemoryAccessCounts(start_idx, memory_size, address_witnesses) => {
                let mut memory_read_counts = vec![0u32; *memory_size];
                for addr_witness_idx in address_witnesses {
                    let addr = witness[*addr_witness_idx].try_to_u64().unwrap() as usize;
                    memory_read_counts[addr] += 1;
                }
                for (i, count) in memory_read_counts.iter().enumerate() {
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
        }
    }
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
