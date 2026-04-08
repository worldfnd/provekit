mod ram;
pub(crate) mod ram_twist;
mod rom;

pub(crate) use {ram::add_ram_checking, rom::add_rom_checking};

/// Selects the RAM (read-write memory) checking method.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RamCheckingMethod {
    /// SPICE grand-product permutation argument (default).
    #[default]
    Spice,
    /// Twist sumcheck-native sorted-trace argument (ePrint 2025/105).
    Twist,
}

#[derive(Debug, Clone)]
pub enum MemoryOperation {
    /// (R1CS witness index of address, R1CS witness index of value read)
    Load(usize, usize),
    /// (R1CS witness index of address, R1CS witness index of value to write)
    Store(usize, usize),
}

#[derive(Debug, Clone)]
/// Used for tracking operations on a memory block.
pub struct MemoryBlock {
    /// The R1CS witnesses corresponding to the memory block values
    pub initial_value_witnesses: Vec<usize>,
    /// The memory operations, in the order that they occur
    pub operations:              Vec<MemoryOperation>,
}

impl MemoryBlock {
    pub fn new() -> Self {
        Self {
            initial_value_witnesses: vec![],
            operations:              vec![],
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.operations.iter().all(|op| match op {
            MemoryOperation::Load(..) => true,
            MemoryOperation::Store(..) => false,
        })
    }
}
