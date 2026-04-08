//! Twist: sumcheck-native read-write memory checking protocol.
//!
//! Based on the "Twist and Shout" paper (Setty, Thaler, Arun — ePrint 2025/105).
//!
//! Twist verifies RAM (read-write memory) consistency without grand-product
//! permutation arguments (SPICE). Instead, it uses:
//!
//! 1. **Sorted trace**: Memory operations sorted by (address, timestamp).
//! 2. **Inc vector**: Binary indicator — `Inc[j] = 1` iff `sorted[j]` and
//!    `sorted[j-1]` share the same address.
//! 3. **Val consistency**: When `Inc[j] = 1`, consecutive reads to the same
//!    address must return the same value (unless a write intervenes).
//!
//! The protocol runs as a sumcheck alongside the R1CS/WHIR sumcheck, sharing
//! the Fiat-Shamir transcript. No Fiat-Shamir challenges are needed before
//! witness commitment, so all witnesses can live in w1.
//!
//! # Soundness Note
//!
//! The current implementation verifies **internal consistency** of the sorted
//! trace (value and address checks) but does NOT include a **permutation
//! argument** linking the sorted trace to the actual memory operations in the
//! R1CS execution trace. The full Jolt protocol (Section 5.3) uses a LogUp
//! multiset equality check for this purpose.
//!
//! Without the permutation argument, a malicious prover can commit to a valid
//! but unrelated sorted trace. This is sound for honest provers (the prover
//! constructs the trace from the actual execution) but **not sound against
//! adversarial provers**. A permutation argument must be added before this
//! can be used in production.

pub mod sumcheck;

use {
    crate::FieldElement,
    ark_std::{One, Zero},
    serde::{Deserialize, Serialize},
};

/// A single memory operation in the execution trace.
#[derive(Clone, Debug)]
pub struct MemoryOp {
    /// Address being accessed (as a field element index).
    pub address: usize,
    /// Value read or written.
    pub value: FieldElement,
    /// Whether this is a write (true) or read (false).
    pub is_write: bool,
    /// Global timestamp (execution order index).
    pub timestamp: usize,
}

/// The sorted memory trace with auxiliary data needed for Twist verification.
#[derive(Clone, Debug)]
pub struct TwistTrace {
    /// Memory operations sorted by (address, timestamp).
    pub sorted_ops: Vec<MemoryOp>,
    /// Inc[j] = 1 iff sorted_ops[j].address == sorted_ops[j-1].address.
    /// Inc[0] = 0 always.
    pub inc: Vec<FieldElement>,
    /// Number of distinct memory cells.
    pub memory_size: usize,
}

impl TwistTrace {
    /// Build a Twist trace from an unsorted list of memory operations and
    /// initial memory values.
    ///
    /// The trace includes initial writes (timestamp 0 for each cell) followed
    /// by the actual operations. The full trace is then sorted by
    /// (address, timestamp) and the Inc vector is derived.
    pub fn from_operations(
        initial_values: &[FieldElement],
        operations: &[MemoryOp],
    ) -> Self {
        let memory_size = initial_values.len();

        // Build full trace: initial writes + operations
        let mut all_ops: Vec<MemoryOp> = Vec::with_capacity(memory_size + operations.len());

        // Initial writes at timestamp 0
        for (addr, &value) in initial_values.iter().enumerate() {
            all_ops.push(MemoryOp {
                address: addr,
                value,
                is_write: true,
                timestamp: 0,
            });
        }

        // Actual operations (timestamps start at 1)
        for op in operations {
            all_ops.push(op.clone());
        }

        // Sort by (address, timestamp)
        all_ops.sort_by_key(|op| (op.address, op.timestamp));

        // Compute Inc vector
        let mut inc = vec![FieldElement::zero(); all_ops.len()];
        for j in 1..all_ops.len() {
            if all_ops[j].address == all_ops[j - 1].address {
                inc[j] = FieldElement::one();
            }
        }

        TwistTrace {
            sorted_ops: all_ops,
            inc,
            memory_size,
        }
    }

    /// Verify that the trace is internally consistent:
    /// - For consecutive operations to the same address, reads return the last
    ///   written value.
    /// - Timestamps are strictly increasing within each address.
    ///
    /// This is a prover-side sanity check, not the cryptographic verification.
    pub fn check_consistency(&self) -> bool {
        for j in 1..self.sorted_ops.len() {
            let prev = &self.sorted_ops[j - 1];
            let curr = &self.sorted_ops[j];

            if curr.address == prev.address {
                // Timestamps must be strictly increasing
                if curr.timestamp <= prev.timestamp {
                    return false;
                }
                // If current is a read, value must match previous
                if !curr.is_write && curr.value != prev.value {
                    return false;
                }
            }
        }
        true
    }

    /// Total trace length (initial writes + operations).
    pub fn len(&self) -> usize {
        self.sorted_ops.len()
    }

    /// Whether the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.sorted_ops.is_empty()
    }

}

/// Number of polynomials committed for Twist (inc, is_write, val, val_prev,
/// addr, addr_prev).
pub const NUM_TWIST_POLYS: usize = 6;

/// Metadata describing where Twist polynomials are stored within the witness
/// vector and how the Twist sumcheck is parameterized.
///
/// The 6 polynomials are stored contiguously starting at `poly_offset`:
/// `[inc..., is_write..., val..., val_prev..., addr..., addr_prev...]`
/// Each polynomial has `trace_size_padded` elements.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TwistSchemeInfo {
    /// Index into the R1CS witness where the first Twist polynomial starts.
    pub poly_offset: usize,
    /// Padded trace length (next power of 2 of memory_size + num_operations).
    pub trace_size_padded: usize,
    /// log2(trace_size_padded).
    pub num_vars: usize,
    /// Total number of witness slots consumed: `NUM_TWIST_POLYS *
    /// trace_size_padded`.
    pub total_witnesses: usize,
    /// Description of each RAM block contributing to this Twist instance.
    pub ram_blocks: Vec<TwistRamBlockInfo>,
}

/// Information about a single RAM block, used to reconstruct the memory trace
/// at prove time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TwistRamBlockInfo {
    /// Witness indices of initial memory values (one per cell).
    pub initial_value_witnesses: Vec<usize>,
    /// Memory operations in execution order.
    pub operations: Vec<TwistMemoryOpInfo>,
}

/// A memory operation recorded during R1CS compilation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TwistMemoryOpInfo {
    /// Load(address_witness, value_witness)
    Load(usize, usize),
    /// Store(address_witness, old_value_witness, new_value_witness)
    Store(usize, usize, usize),
}

impl TwistSchemeInfo {
    /// Build a `TwistSchemeInfo` given the RAM block metadata and the current
    /// witness count (where the Twist polynomials will start).
    pub fn new(poly_offset: usize, ram_blocks: Vec<TwistRamBlockInfo>) -> Self {
        // Total trace = sum of (memory_size + num_ops) across all blocks
        let total_trace: usize = ram_blocks
            .iter()
            .map(|b| b.initial_value_witnesses.len() + b.operations.len())
            .sum();
        let trace_size_padded = total_trace.next_power_of_two();
        let num_vars = trace_size_padded.trailing_zeros() as usize;
        let total_witnesses = NUM_TWIST_POLYS * trace_size_padded;
        Self {
            poly_offset,
            trace_size_padded,
            num_vars,
            total_witnesses,
            ram_blocks,
        }
    }

    /// Offset of the i-th Twist polynomial (0=inc, 1=is_write, 2=val,
    /// 3=val_prev, 4=addr, 5=addr_prev).
    pub fn poly_start(&self, i: usize) -> usize {
        self.poly_offset + i * self.trace_size_padded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twist_trace_simple() {
        // Memory of size 2, initial values [10, 20]
        let initial = [FieldElement::from(10u64), FieldElement::from(20u64)];

        // Read addr 0 (should get 10), Write addr 1 = 30, Read addr 1 (should get 30)
        let ops = vec![
            MemoryOp {
                address: 0,
                value: FieldElement::from(10u64),
                is_write: false,
                timestamp: 1,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(30u64),
                is_write: true,
                timestamp: 2,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(30u64),
                is_write: false,
                timestamp: 3,
            },
        ];

        let trace = TwistTrace::from_operations(&initial, &ops);

        // Sorted: (0,0,W,10), (0,1,R,10), (1,0,W,20), (1,2,W,30), (1,3,R,30)
        assert_eq!(trace.len(), 5);
        assert!(trace.check_consistency());

        // Inc: [0, 1, 0, 1, 1]
        assert_eq!(trace.inc[0], FieldElement::zero());
        assert_eq!(trace.inc[1], FieldElement::one()); // same addr as prev
        assert_eq!(trace.inc[2], FieldElement::zero()); // new addr
        assert_eq!(trace.inc[3], FieldElement::one()); // same addr
        assert_eq!(trace.inc[4], FieldElement::one()); // same addr
    }

    #[test]
    fn test_twist_trace_inconsistent_read() {
        let initial = [FieldElement::from(10u64)];

        // Read addr 0 with wrong value (should be 10, not 99)
        let ops = vec![MemoryOp {
            address: 0,
            value: FieldElement::from(99u64),
            is_write: false,
            timestamp: 1,
        }];

        let trace = TwistTrace::from_operations(&initial, &ops);
        assert!(!trace.check_consistency());
    }
}
