use {
    ark_ff::PrimeField,
    provekit_common::{
        witness::{SpiceMemoryOperation, SpiceWitnesses},
        FieldElement,
    },
};

pub(crate) trait SpiceWitnessesSolver {
    fn solve(&self, witness: &mut [Option<FieldElement>]);
}

impl SpiceWitnessesSolver for SpiceWitnesses {
    fn solve(&self, witness: &mut [Option<FieldElement>]) {
        // Read from actual witness indices (may be non-contiguous)
        let mut rv_final: Vec<Option<FieldElement>> = self
            .initial_value_witnesses
            .iter()
            .map(|&idx| witness[idx])
            .collect();
        let mut rt_final = vec![0; self.memory_length];
        for (mem_op_index, mem_op) in self.memory_operations.iter().enumerate() {
            match mem_op {
                SpiceMemoryOperation::Load(addr_idx, value_idx, read_timestamp_idx) => {
                    let addr = witness[*addr_idx].unwrap();
                    let addr_as_usize = addr.into_bigint().0[0] as usize;
                    witness[*read_timestamp_idx] =
                        Some(FieldElement::from(rt_final[addr_as_usize] as u64));
                    rv_final[addr_as_usize] = witness[*value_idx];
                    rt_final[addr_as_usize] = mem_op_index + 1;
                }
                SpiceMemoryOperation::Store(
                    addr_idx,
                    old_value_idx,
                    new_value_idx,
                    read_timestamp_idx,
                ) => {
                    let addr = witness[*addr_idx].unwrap();
                    let addr_as_usize = addr.into_bigint().0[0] as usize;
                    witness[*old_value_idx] = rv_final[addr_as_usize];
                    witness[*read_timestamp_idx] =
                        Some(FieldElement::from(rt_final[addr_as_usize] as u64));
                    let new_value = witness[*new_value_idx];
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
