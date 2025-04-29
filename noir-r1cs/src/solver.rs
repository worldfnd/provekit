use std::{collections::BTreeMap, mem};

use acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    };
use rand::Rng;

use crate::compiler::MemoryOperation;

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
    /// The factors of the multiset check used in read/write memory checking.
    /// Values: (sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness))
    /// where sz_challenge, rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes: sz_challenge - (addr * addr_witness + rs_challenge * value + rs_challenge * rs_challenge * timer * timer_witness)
    MemOpMultisetFactor(usize, usize, (FieldElement, usize), usize, (FieldElement, usize)),
    /// The timestamp of a memory read (used for read/write memory checking)
    /// Fields are (block id, (raw address, address witness index), only one of which can be non-zero)

    /// (memory_length, initial values start, memory operations, rv_final_start, rt_final_start) FIXME rename MemoryOperationWitnesses?
    SpiceWitnesses(usize, usize, Vec<MemoryOperation>, usize, usize), 
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness vector.
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
            WitnessBuilder::MemOpMultisetFactor(_, _, _, _, _) => 1,
            WitnessBuilder::SpiceWitnesses(memory_length, _, mem_ops, _, _) => mem_ops.len() * 2 + memory_length, // what about rv?  what about implicit vs explicit?
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
                    dbg!(addr_witness_idx, addr);
                    memory_read_counts[addr] += 1;
                }
                for (i, count) in memory_read_counts.iter().enumerate() {
                    witness[start_idx + i] = FieldElement::from(*count);
                }
            }
            WitnessBuilder::MemOpMultisetFactor(sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness)) => {
                witness[start_idx] = witness[*sz_challenge] - (*addr * witness[*addr_witness]
                    + witness[*rs_challenge] * witness[*value]
                    + witness[*rs_challenge] * witness[*rs_challenge] * *timer * witness[*timer_witness]);
            }
            WitnessBuilder::SpiceWitnesses(memory_length, initial_values_start, mem_ops, rv_final_start, rt_final_start) => {
                let mut rv_final = witness[*initial_values_start..*initial_values_start + *memory_length].to_vec();
                let mut rt_final = vec![0; *memory_length];
                for (mem_op_index, mem_op) in mem_ops.iter().enumerate() {
                    match mem_op {
                        MemoryOperation::Load(addr, value, read_timestamp) => {
                            let addr = witness[*addr];
                            let addr_as_usize = addr.try_to_u64().unwrap() as usize;
                            witness[*read_timestamp] = FieldElement::from(rt_final[addr_as_usize]);
                            rv_final[addr_as_usize] = witness[*value];
                            rt_final[addr_as_usize] = mem_op_index + 1;
                        }
                        MemoryOperation::Store(addr, old_value, new_value, read_timestamp) => {
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
                for i in 0..*memory_length {
                    witness[*rv_final_start + i] = rv_final[i];
                    witness[*rt_final_start + i] = FieldElement::from(rt_final[i]);
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
