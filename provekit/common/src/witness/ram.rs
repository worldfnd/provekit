use serde::{Deserialize, Serialize};

/// Like MemoryOperation, but with the indices of the additional witnesses
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
