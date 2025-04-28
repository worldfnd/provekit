use {
    acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    }, core::time, std::{collections::BTreeMap, mem}
};
use rand::Rng;

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
    /// Witness is the result of a memory read from the .0th block at the address determined by the .1th R1CS witness, whose value is available as the .2th ACIR witness index
    /// Implementation note: it would be insufficient to just record the ACIR witness index, since the solver needs to be able to simulate the memory accesses (updating the stored timestamps, in particular).
    ExplicitReadValueFromMemory(usize, usize, usize),
    /// Witness is the result of a memory read from the .0th block at the address determined by the
    /// .1th R1CS witness, whose value the R1CS solver needs to determine via memory simulation.
    ImplicitReadValueFromMemory(usize, usize),
    /// The number of times that the .1th index of the .0th memory block is accessed
    MemoryReadCount(usize, usize),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (sz_challenge, (index_coeff, index), rs_challenge, value).
    LogUpDenominator(usize, (FieldElement, usize), usize, usize),
    /// Witness is the value written to the .0th block of memory at the address determined by the .1th R1CS witness, whose value is available as the .2th acir witness index
    /// Implementation note: it would be insufficient to just record the ACIR witness index, since the solver needs to be able to simulate the memory accesses (updating the stored timestamps, in particular).
    ExplicitWriteValueToMemory(usize, usize, usize),
    /// The factors of the multiset check used in read/write memory checking.
    /// Values: (sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness))
    /// where sz_challenge, rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes: sz_challenge - (addr * addr_witness + rs_challenge * value + rs_challenge * rs_challenge * timer * timer_witness)
    MemOpMultisetFactor(usize, usize, (FieldElement, usize), usize, (FieldElement, usize)),
    /// The timestamp of a memory read (used for read/write memory checking)
    /// Fields are (block id, (raw address, address witness index), only one of which can be non-zero)
    MemoryReadTimestamp(usize, (usize, usize)),
    /// The final timestamp of a memory read (used for read/write memory checking)
    /// Fields are (block id, raw address), only one of which can be non-zero)
    FinalMemoryReadTimestamp(usize, usize),
    /// The final value of a memory cell (used for read/write memory checking)
    /// Fields are block id and address (not a witness index!)
    FinalMemoryValue(usize, usize),
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

pub struct R1CSSolver {
    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    /// The ACIR witness indices of the initial values of the memory blocks
    pub initial_memories: BTreeMap<usize, Vec<usize>>
}

impl R1CSSolver {
    pub fn new() -> Self {
        Self {
            witness_builders: vec![WitnessBuilder::Constant(FieldElement::one())],
            initial_memories: BTreeMap::new(),
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
            .initial_memories
            .iter()
            .map(|(block_id, initial_values)| (*block_id, vec![0u32; initial_values.len()]))
            .collect();

        // The (value, timer(=0)) memory state for each block of memory
        // Initial values determined by the ACIR witness
        let mut memory_state = self.initial_memories.iter().map(|(block_id, initial_value_witnesses)| {
            let memory = initial_value_witnesses
                .iter()
                .map(|witness_idx| (acir_witnesses[&AcirWitness(*witness_idx as u32)], 0u32))
                .collect::<Vec<_>>();
            (*block_id, memory)
        }).collect::<BTreeMap<_, _>>();

        let mut next_write_timestamp = 1u32;

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
                    WitnessBuilder::ExplicitReadValueFromMemory(
                        block_id,
                        addr_witness_idx,
                        value_acir_witness_idx,
                    ) => {
                        let addr =
                            witness[*addr_witness_idx].unwrap().try_to_u64().unwrap() as usize;
                        // Increment the memory read count (this for memory checking read-only memory)
                        memory_read_counts.get_mut(block_id).unwrap()[addr] += 1;
                        acir_witnesses[&AcirWitness(*value_acir_witness_idx as u32)]
                    }
                    WitnessBuilder::ImplicitReadValueFromMemory(
                        block_id,
                        addr_witness_idx,
                    ) => {
                        let addr =
                            witness[*addr_witness_idx].unwrap().try_to_u64().unwrap() as usize;
                        let value = memory_state.get(block_id).unwrap()[addr].0;
                        // Note: we don't change the value of mem_op_timer here since this will be
                        // handled by the ExplicitWriteValueToMemory associated this this
                        // ImplicitReadValueFromMemory.
                        value
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
                    WitnessBuilder::MemoryReadCount(block_id, addr) => {
                        let count = memory_read_counts.get(block_id).unwrap()[*addr];
                        FieldElement::from(count)
                    }
                    WitnessBuilder::LogUpDenominator(
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
                    WitnessBuilder::ExplicitWriteValueToMemory(
                        block_id,
                        addr_witness_idx,
                        value_acir_witness_idx,
                    ) => {
                        let addr =
                            witness[*addr_witness_idx].unwrap().try_to_u64().unwrap() as usize;
                        let value = acir_witnesses[&AcirWitness(*value_acir_witness_idx as u32)];
                        // Track the change to the memory state
                        let memory = memory_state.get_mut(block_id).unwrap();
                        memory[addr] = (value, memory[addr].1);
                        value
                    }
                    WitnessBuilder::MemOpMultisetFactor(sz_challenge, rs_challenge, (addr, addr_witness), value, (timer, timer_witness)) => {
                        let sz_challenge = witness[*sz_challenge].unwrap();
                        let rs_challenge = witness[*rs_challenge].unwrap();
                        let addr_witness = witness[*addr_witness].unwrap();
                        let value = witness[*value].unwrap();
                        let timer_witness = witness[*timer_witness].unwrap();
                        sz_challenge - (*addr * addr_witness
                            + rs_challenge * value
                            + rs_challenge * rs_challenge * *timer * timer_witness)
                    }
                    WitnessBuilder::MemoryReadTimestamp(block_id, (addr, addr_witness)) => {
                        let addr = if *addr_witness == self.witness_one() {
                            *addr
                        } else {
                            witness[*addr_witness].unwrap().try_to_u64().unwrap() as usize
                        };
                        let timer = memory_state.get(block_id).unwrap()[addr].1;
                        println!("MemoryReadTimestamp: setting timestamp at addr {addr} to {next_write_timestamp}");
                        memory_state.get_mut(block_id).unwrap()[addr].1 = next_write_timestamp;
                        next_write_timestamp += 1;
                        FieldElement::from(timer)
                    }
                    WitnessBuilder::FinalMemoryReadTimestamp(block_id, addr) => {
                        let timer = memory_state.get(block_id).unwrap()[*addr].1;
                        FieldElement::from(timer)
                    }
                    WitnessBuilder::FinalMemoryValue(block_id, addr) => {
                        memory_state.get(block_id).unwrap()[*addr].0
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
