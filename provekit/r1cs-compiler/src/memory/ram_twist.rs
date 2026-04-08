//! RAM checking via Twist: allocates witnesses for Twist polynomials and
//! records memory trace metadata, WITHOUT generating SPICE constraints.
//!
//! The Twist polynomials (inc, is_write, val, val_prev, addr, addr_prev) are
//! stored as "free" witnesses in the R1CS — unconstrained by any R1CS
//! constraint. Their consistency is verified by a separate Twist sumcheck
//! that runs alongside the WHIR sumcheck.
//!
//! # Soundness Note
//!
//! This module adds **zero R1CS constraints** for RAM operations. Memory
//! consistency is verified entirely by the Twist sumcheck (see
//! [`provekit_common::twist`]). However, the current implementation does NOT
//! include a **permutation argument** linking the Twist sorted trace to the
//! actual execution trace. See the soundness note in `twist/mod.rs` for
//! details.

use {
    crate::{memory::MemoryBlock, noir_to_r1cs::NoirToR1CSCompiler},
    ark_std::Zero,
    provekit_common::{
        twist::{TwistMemoryOpInfo, TwistRamBlockInfo, TwistSchemeInfo},
        witness::{ConstantTerm, WitnessBuilder},
        FieldElement,
    },
    tracing::debug,
};

/// Add witnesses for Twist-based RAM checking.
///
/// Instead of SPICE's grand-product constraints, this:
/// 1. Records memory operation metadata (which witnesses are addresses/values).
/// 2. Allocates `6 * trace_size_padded` placeholder witnesses for the Twist
///    polynomials (filled by the prover at prove time).
/// 3. Returns `TwistSchemeInfo` describing the layout.
///
/// No range checks are needed (Twist handles ordering via the sorted trace).
#[tracing::instrument(skip_all)]
pub fn add_ram_checking_twist(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    blocks: &[&MemoryBlock],
) -> TwistSchemeInfo {
    let mut ram_blocks = Vec::with_capacity(blocks.len());
    // Collect all witness indices that fill_twist_witnesses will read.
    // These must be in w1 so they're solved before Twist filling.
    let mut twist_reads = Vec::new();

    for block in blocks {
        // Initial value witnesses are read to simulate memory state
        twist_reads.extend_from_slice(&block.initial_value_witnesses);

        let mut operations = Vec::with_capacity(block.operations.len());
        for op in &block.operations {
            match op {
                crate::memory::MemoryOperation::Load(addr_witness, value_witness) => {
                    twist_reads.push(*addr_witness);
                    twist_reads.push(*value_witness);
                    operations.push(TwistMemoryOpInfo::Load(*addr_witness, *value_witness));
                }
                crate::memory::MemoryOperation::Store(addr_witness, new_value_witness) => {
                    twist_reads.push(*addr_witness);
                    twist_reads.push(*new_value_witness);
                    // For stores, allocate an old_value witness via a Constant(0) builder.
                    // The prover overwrites this during fill_twist_witnesses.
                    let old_value = r1cs_compiler.add_witness_builder(
                        WitnessBuilder::Constant(ConstantTerm(
                            r1cs_compiler.num_witnesses(),
                            FieldElement::zero(),
                        )),
                    );
                    operations.push(TwistMemoryOpInfo::Store(
                        *addr_witness,
                        old_value,
                        *new_value_witness,
                    ));
                }
            }
        }

        ram_blocks.push(TwistRamBlockInfo {
            initial_value_witnesses: block.initial_value_witnesses.clone(),
            operations,
        });
    }

    // Allocate witness slots for the 6 Twist polynomials via a Placeholder
    // builder. The `reads` field ensures the splitter places all referenced
    // witnesses into w1 alongside the Placeholder.
    let poly_offset = r1cs_compiler.num_witnesses();
    let twist_info = TwistSchemeInfo::new(poly_offset, ram_blocks);

    debug!(
        poly_offset,
        trace_size_padded = twist_info.trace_size_padded,
        total_witnesses = twist_info.total_witnesses,
        "Allocating Twist polynomial witnesses"
    );

    r1cs_compiler.add_witness_builder(WitnessBuilder::Placeholder {
        start: poly_offset,
        count: twist_info.total_witnesses,
        reads: twist_reads,
    });

    twist_info
}
