use {
    crate::{
        memory::{MemoryBlock, MemoryOperation},
        noir_to_r1cs::NoirToR1CSCompiler,
        r1cs_solver::{SumTerm, WitnessBuilder, WitnessCoefficient},
        FieldElement,
    },
    ark_ff::{One, PrimeField, Zero},
    serde::{Deserialize, Serialize},
    std::ops::Neg,
};

/// Like [MemoryOperation], but with the indices of the additional witnesses
/// needed by Spice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpiceMemoryOperation {
    /// Load operation.  Arguments are R1CS witness indices:
    /// (address, value read, read timestamp)
    /// `address` is already solved for by the ACIR solver.
    Load(usize, usize, usize),
    /// Store operation.  Arguments are R1CS witness indices:
    /// (address, old value, new value, read timestamp)
    /// `address`, `old value`, `new value` are already solved for by the ACIR
    /// solver.
    Store(usize, usize, usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpiceWitnesses {
    /// The length of the memory block
    pub memory_length:        usize,
    /// The witness index of the first initial value (they are stored
    /// contiguously) (Not written to)
    pub initial_values_start: usize,
    /// The memory operations, in the order that they occur; each
    /// SpiceMemoryOperation contains witness indices that will be written to)
    pub memory_operations:    Vec<SpiceMemoryOperation>,
    /// The witness index of the first of the memory_length final read values
    /// (stored contiguously) (these witnesses are written to)
    pub rv_final_start:       usize,
    /// The witness index of the first of the memory_length final read
    /// timestamps (stored contiguously) (these witnesses are written to)
    pub rt_final_start:       usize,
    /// The index of the first witness written to by the SpiceWitnesses struct
    pub first_witness_idx:    usize,
    /// The number of witnesses written to by the SpiceWitnesses struct
    pub num_witnesses:        usize,
}

impl SpiceWitnesses {
    pub fn new(
        mut next_witness_idx: usize,
        memory_length: usize,
        initial_values_start: usize,
        memory_operations: Vec<MemoryOperation>,
    ) -> Self {
        let start_witness_idx = next_witness_idx;

        let spice_memory_operations = memory_operations
            .into_iter()
            .map(|op| match op {
                MemoryOperation::Load(addr, value) => {
                    let op = SpiceMemoryOperation::Load(addr, value, next_witness_idx);
                    next_witness_idx += 1;
                    op
                }
                MemoryOperation::Store(addr, new_value) => {
                    let old_value = next_witness_idx;
                    next_witness_idx += 1;
                    let read_timestamp = next_witness_idx;
                    next_witness_idx += 1;
                    SpiceMemoryOperation::Store(addr, old_value, new_value, read_timestamp)
                }
            })
            .collect();
        let rv_final_start = next_witness_idx;
        next_witness_idx += memory_length;
        let rt_final_start = next_witness_idx;
        next_witness_idx += memory_length;
        let num_witnesses = next_witness_idx - start_witness_idx;

        Self {
            memory_length,
            initial_values_start,
            memory_operations: spice_memory_operations,
            rv_final_start,
            rt_final_start,
            first_witness_idx: start_witness_idx,
            num_witnesses,
        }
    }

    /// Solve for the values of the Spice witnesses.
    pub fn solve(&self, witness: &mut [Option<FieldElement>]) {
        let mut rv_final = witness
            [self.initial_values_start..self.initial_values_start + self.memory_length]
            .to_vec();
        let mut rt_final = vec![0; self.memory_length];
        for (mem_op_index, mem_op) in self.memory_operations.iter().enumerate() {
            match mem_op {
                SpiceMemoryOperation::Load(addr, value, read_timestamp) => {
                    let addr = witness[*addr].unwrap();
                    let addr_as_usize = addr.into_bigint().0[0] as usize;
                    witness[*read_timestamp] =
                        Some(FieldElement::from(rt_final[addr_as_usize] as u64));
                    rv_final[addr_as_usize] = witness[*value];
                    rt_final[addr_as_usize] = mem_op_index + 1;
                }
                SpiceMemoryOperation::Store(addr, old_value, new_value, read_timestamp) => {
                    let addr = witness[*addr].unwrap();
                    let addr_as_usize = addr.into_bigint().0[0] as usize;
                    witness[*old_value] = rv_final[addr_as_usize];
                    witness[*read_timestamp] =
                        Some(FieldElement::from(rt_final[addr_as_usize] as u64));
                    let new_value = witness[*new_value];
                    rv_final[addr_as_usize] = new_value;
                    rt_final[addr_as_usize] = mem_op_index + 1;
                }
            }
        }
        // Copy the final values and read timestamps into the witness vector
        for i in 0..self.memory_length {
            witness[self.rv_final_start + i] = rv_final[i];
            witness[self.rt_final_start + i] = Some(FieldElement::from(rt_final[i] as u64));
        }
    }
}

/// Add witnesses and constraints ensuring the integrity of read/write
/// operations on a memory block, using the Spice offline memory checking
/// protocol. The final range checks are left to the calling context.
/// Returns (range_check_num_bits, witness_indices_to_range_check).
pub fn add_ram_checking(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    block: &MemoryBlock,
) -> (u32, Vec<usize>) {
    // Add two verifier challenges for the multiset check
    let rs_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let rs_challenge_sqrd = r1cs_compiler.add_product(rs_challenge, rs_challenge);
    let sz_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));

    // The current witnesses indices for the partial products of the read set (RS)
    // hash and the write set (WS) hash
    let mut rs_hash = r1cs_compiler.witness_one();
    let mut ws_hash = r1cs_compiler.witness_one();

    let memory_length = block.initial_value_witnesses.len();

    // Track all the (mem_op_index, read timestamp) pairs so we can perform the two
    // required range checks later.
    let mut all_mem_op_index_and_rt = vec![];

    println!("INIT");
    // For each of the writes in the inititialization, add a factor to the write
    // hash
    block
        .initial_value_witnesses
        .iter()
        .enumerate()
        .for_each(|(addr, mem_value)| {
            // Initial PUTs. These all use timestamp zero.
            let factor = add_mem_op_multiset_factor(
                r1cs_compiler,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                (FieldElement::from(addr as u64), r1cs_compiler.witness_one()),
                *mem_value,
                (FieldElement::zero(), r1cs_compiler.witness_one()),
            );
            println!("WS factor [{}]: ({}, [{}], 0)", factor, addr, mem_value);
            ws_hash = r1cs_compiler.add_product(ws_hash, factor);
        });

    let spice_witnesses = SpiceWitnesses::new(
        r1cs_compiler.num_witnesses(),
        memory_length,
        block.initial_value_witnesses[0],
        block.operations.clone(),
    );
    r1cs_compiler.add_witness_builder(WitnessBuilder::SpiceWitnesses(spice_witnesses.clone()));

    spice_witnesses
        .memory_operations
        .iter()
        .enumerate()
        .for_each(|(mem_op_index, op)| {
            match op {
                SpiceMemoryOperation::Load(addr_witness, value_witness, rt_witness) => {
                    println!("LOAD (mem op {})", mem_op_index);
                    // GET
                    all_mem_op_index_and_rt.push((mem_op_index, *rt_witness));
                    let factor = add_mem_op_multiset_factor(
                        r1cs_compiler,
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::one(), *addr_witness),
                        *value_witness,
                        (FieldElement::one(), *rt_witness),
                    );
                    println!(
                        "RS factor [{}]: ([{}], [{}], [{}])",
                        factor, addr_witness, value_witness, rt_witness
                    );
                    rs_hash = r1cs_compiler.add_product(rs_hash, factor);

                    // PUT
                    let factor = add_mem_op_multiset_factor(
                        r1cs_compiler,
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::one(), *addr_witness),
                        *value_witness,
                        (
                            FieldElement::from((mem_op_index + 1) as u64),
                            r1cs_compiler.witness_one(),
                        ),
                    );
                    println!(
                        "WS factor [{}]: ([{}], [{}], {})",
                        factor,
                        addr_witness,
                        value_witness,
                        mem_op_index + 1
                    );
                    ws_hash = r1cs_compiler.add_product(ws_hash, factor);
                }
                SpiceMemoryOperation::Store(
                    addr_witness,
                    old_value_witness,
                    new_value_witness,
                    rt_witness,
                ) => {
                    println!("STORE (mem op {})", mem_op_index);
                    // GET
                    all_mem_op_index_and_rt.push((mem_op_index, *rt_witness));
                    let factor = add_mem_op_multiset_factor(
                        r1cs_compiler,
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::one(), *addr_witness),
                        *old_value_witness,
                        (FieldElement::one(), *rt_witness),
                    );
                    println!(
                        "RS factor [{}]: ([{}], [{}], [{}])",
                        factor, addr_witness, old_value_witness, rt_witness
                    );
                    rs_hash = r1cs_compiler.add_product(rs_hash, factor);

                    // PUT
                    let factor = add_mem_op_multiset_factor(
                        r1cs_compiler,
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::one(), *addr_witness),
                        *new_value_witness,
                        (
                            FieldElement::from((mem_op_index + 1) as u64),
                            r1cs_compiler.witness_one(),
                        ),
                    );
                    println!(
                        "WS factor [{}]: ([{}], [{}], {})",
                        factor,
                        addr_witness,
                        new_value_witness,
                        mem_op_index + 1
                    );
                    ws_hash = r1cs_compiler.add_product(ws_hash, factor);
                }
            }
        });

    println!("AUDIT");
    // audit(): for each of the cells of the memory block, add a factor to the read
    // hash We don't need to keep incrementing the mem op index, since only GET
    // operations remain. TODO: see what global timestamp is used in the AUDIT
    // phase of the Spice protocol (check the Jolt implementation).
    (0..memory_length).for_each(|addr| {
        // GET
        let value_witness = spice_witnesses.rv_final_start + addr;
        let rt_witness = spice_witnesses.rt_final_start + addr;
        all_mem_op_index_and_rt.push((block.operations.len(), rt_witness));
        let factor = add_mem_op_multiset_factor(
            r1cs_compiler,
            sz_challenge,
            rs_challenge,
            rs_challenge_sqrd,
            (FieldElement::from(addr as u64), r1cs_compiler.witness_one()),
            value_witness,
            (FieldElement::one(), rt_witness),
        );
        println!(
            "RS factor [{}]: ({}, [{}], [{}])",
            factor, addr, value_witness, rt_witness
        );
        rs_hash = r1cs_compiler.add_product(rs_hash, factor);
    });

    // Add the final constraint to enforce that the hashes are equal
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), rs_hash)],
        &[(FieldElement::one(), ws_hash)],
    );

    // We want to establish that mem_op_index = max(mem_op_index, retrieved_timer)
    // Or equivalently, that mem_op_index - retrieved_timer >= 0
    // We do this via two separate range checks:
    //  1. retrieved_timer in 0..2^K
    //  2. (mem_op_index - retrieved_timer) in 0..2^K
    // where K is minimal such that 2^K >= block.operations.len().
    // The above range check is sound so long as 2^K is less than the characteristic
    // of the field. (Note that range checks implemented only for powers of
    // two). The maximum value obtained by the global timestamp is the number of
    // memory operations. This is also the maximum value for any valid read
    // timestamp.

    // num_bits is the ceil log of one more than the maximum permitted value
    let num_bits = (block.operations.len() + 1).next_power_of_two().ilog2();
    let mut range_check = Vec::with_capacity(2 * all_mem_op_index_and_rt.len());
    all_mem_op_index_and_rt
        .iter()
        .for_each(|(mem_op_index, rt_witness)| {
            // Implementation note: we use an auxiliary witness to represent
            // mem_op_index - rt_witness, in order to interface with the range checking
            // code below.
            let difference_witness_idx = r1cs_compiler.add_sum(vec![
                SumTerm(
                    Some(FieldElement::from(*mem_op_index as u64)),
                    r1cs_compiler.witness_one(),
                ),
                SumTerm(Some(FieldElement::one().neg()), *rt_witness),
            ]);
            range_check.push(*rt_witness);
            range_check.push(difference_witness_idx);
        });
    (num_bits, range_check)
}

// Add and return a new witness representing `sz_challenge - hash`, where `hash`
// is the hash value of a memory operation, adding an R1CS constraint enforcing
// this.
fn add_mem_op_multiset_factor(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    sz_challenge: usize,
    rs_challenge: usize,
    rs_challenge_sqrd: usize,
    (addr, addr_witness): (FieldElement, usize),
    value_witness: usize,
    (timer, timer_witness): (FieldElement, usize),
) -> usize {
    let factor = r1cs_compiler.add_witness_builder(WitnessBuilder::SpiceMultisetFactor(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        rs_challenge,
        WitnessCoefficient(addr, addr_witness),
        value_witness,
        WitnessCoefficient(timer, timer_witness),
    ));
    let intermediate = r1cs_compiler.add_product(rs_challenge_sqrd, timer_witness);
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), rs_challenge)],
        &[(FieldElement::one().neg(), value_witness)],
        &[
            (FieldElement::one(), factor),
            (FieldElement::one().neg(), sz_challenge),
            (timer, intermediate),
            (addr, addr_witness),
        ],
    );
    factor
}
