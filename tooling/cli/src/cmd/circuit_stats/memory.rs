//! Memory operation statistics tracking.
//!
//! Tracks read-only memory (ROM) and read-write memory (RAM) operations,
//! computing R1CS constraint and witness costs.

use {
    acir::{circuit::opcodes::BlockType, native_types::Expression, FieldElement},
    std::collections::{HashMap, HashSet},
};

/// Statistics for a single memory block.
#[derive(Default)]
pub(super) struct MemoryBlockStats {
    pub block_type:       Option<BlockType>,
    pub initial_size:     usize,
    pub reads:            usize,
    pub writes:           usize,
    read_indices:         HashSet<String>,
    pub write_after_read: bool,
}

impl MemoryBlockStats {
    pub fn record_init(&mut self, block_type: &BlockType, size: usize) {
        self.block_type = Some(block_type.clone());
        self.initial_size = size;
    }

    pub fn record_read(&mut self, index: &Expression<FieldElement>) {
        self.reads += 1;
        self.read_indices.insert(expression_key(index));
    }

    pub fn record_write(&mut self, index: &Expression<FieldElement>) {
        self.writes += 1;
        let key = expression_key(index);
        if self.read_indices.contains(&key) {
            self.write_after_read = true;
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.writes == 0
    }

    fn total_ops(&self) -> usize {
        self.reads + self.writes
    }

    /// R1CS constraint count for RAM (read-write memory).
    pub fn ram_constraint_count(&self) -> usize {
        7 * (self.initial_size + self.total_ops()) + 2
    }

    /// R1CS witness count for RAM (read-write memory).
    pub fn ram_witness_count(&self) -> usize {
        3 + 9 * self.initial_size + 8 * self.reads + 9 * self.writes
    }

    /// Bit-width required for RAM range checks (timestamp range).
    pub fn ram_range_bits(&self) -> Option<u32> {
        if self.is_read_only() {
            return None;
        }
        let timestamp_limit = self.total_ops();
        Some(timestamp_limit.next_power_of_two().trailing_zeros())
    }

    /// Number of range checks required for RAM.
    pub fn ram_range_check_count(&self) -> usize {
        2 * (self.total_ops() + self.initial_size)
    }

    /// R1CS constraint count for ROM (read-only memory).
    pub fn rom_constraint_count(&self) -> usize {
        2 * self.reads + 3 * self.initial_size + 3
    }

    /// R1CS witness count for ROM (read-only memory).
    pub fn rom_witness_count(&self) -> usize {
        2 * self.reads + 4 * self.initial_size + 4
    }
}

/// Aggregates memory statistics across all blocks.
#[derive(Default)]
pub(super) struct MemoryStats {
    pub blocks: HashMap<u32, MemoryBlockStats>,
}

impl MemoryStats {
    pub fn record_init(&mut self, block_id: u32, block_type: &BlockType, init_len: usize) {
        self.blocks
            .entry(block_id)
            .or_default()
            .record_init(block_type, init_len);
    }

    pub fn record_read(&mut self, block_id: u32, index: &Expression<FieldElement>) {
        self.blocks.entry(block_id).or_default().record_read(index);
    }

    pub fn record_write(&mut self, block_id: u32, index: &Expression<FieldElement>) {
        self.blocks.entry(block_id).or_default().record_write(index);
    }

    pub fn total_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn total_allocated(&self) -> usize {
        self.blocks.values().map(|block| block.initial_size).sum()
    }

    pub fn total_reads(&self) -> usize {
        self.blocks.values().map(|block| block.reads).sum()
    }

    pub fn total_writes(&self) -> usize {
        self.blocks.values().map(|block| block.writes).sum()
    }

    pub fn read_only_block_count(&self) -> usize {
        self.blocks
            .values()
            .filter(|block| block.is_read_only())
            .count()
    }

    pub fn block_summaries(&self) -> Vec<(u32, &MemoryBlockStats)> {
        let mut entries: Vec<_> = self.blocks.iter().map(|(id, block)| (*id, block)).collect();
        entries.sort_by_key(|(id, _)| *id);
        entries
    }

    /// Aggregates R1CS costs across all memory blocks.
    pub fn aggregate(&self) -> MemoryAggregation {
        let mut aggregation = MemoryAggregation::default();

        for (block_id, block) in &self.blocks {
            if block.is_read_only() {
                aggregation.rom_constraints += block.rom_constraint_count();
                aggregation.rom_witnesses += block.rom_witness_count();
            } else {
                aggregation.ram_constraints += block.ram_constraint_count();
                aggregation.ram_witnesses += block.ram_witness_count();

                if let Some(bits) = block.ram_range_bits() {
                    *aggregation.range_checks.entry(bits).or_insert(0) +=
                        block.ram_range_check_count();
                }
            }

            if block.write_after_read {
                aggregation.blocks_with_write_after_read.push(*block_id);
            }
        }

        aggregation.blocks_with_write_after_read.sort_unstable();
        aggregation
    }
}

/// Aggregated memory operation costs.
#[derive(Default)]
pub(super) struct MemoryAggregation {
    pub ram_constraints:              usize,
    pub rom_constraints:              usize,
    pub ram_witnesses:                usize,
    pub rom_witnesses:                usize,
    pub range_checks:                 HashMap<u32, usize>,
    pub blocks_with_write_after_read: Vec<u32>,
}

/// Helper to convert expressions to unique keys for tracking.
fn expression_key(expr: &Expression<FieldElement>) -> String {
    format!("{:?}", expr)
}

/// Formats block type for display.
pub(super) fn describe_block_type(block_type: &BlockType) -> String {
    match block_type {
        BlockType::Memory => "Memory".to_string(),
        BlockType::CallData(size) => format!("CallData({size})"),
        BlockType::ReturnData => "ReturnData".to_string(),
    }
}
