//! RAM checking via Twist: allocates witnesses for Twist polynomials,
//! records memory trace metadata, and adds a LogUp permutation argument
//! linking the sorted trace to the execution trace.
//!
//! The Twist polynomials (inc, is_write, val, val_prev, addr, addr_prev) are
//! stored as "free" witnesses in the R1CS — their consistency is verified by a
//! separate Twist sumcheck. The LogUp permutation argument adds R1CS
//! constraints proving that the multiset of (addr, val, is_write) tuples in
//! the sorted trace equals the multiset from the actual execution trace.

use {
    crate::{memory::MemoryBlock, noir_to_r1cs::NoirToR1CSCompiler},
    ark_std::{One, Zero},
    provekit_common::{
        twist::{TwistMemoryOpInfo, TwistRamBlockInfo, TwistSchemeInfo},
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    tracing::debug,
};

/// Add witnesses for Twist-based RAM checking with LogUp permutation argument.
///
/// This:
/// 1. Records memory operation metadata (which witnesses are addresses/values).
/// 2. Allocates `6 * trace_size_padded` placeholder witnesses for the Twist
///    polynomials (filled by the prover at prove time).
/// 3. Adds a LogUp permutation argument proving the sorted trace matches the
///    execution trace (2 Fiat-Shamir challenges, ~7 witnesses + constraints
///    per memory operation).
/// 4. Returns `TwistSchemeInfo` describing the layout.
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

    // Add LogUp permutation argument linking execution trace to sorted trace.
    add_twist_permutation(r1cs_compiler, &twist_info, blocks);

    twist_info
}

/// Adds a LogUp permutation argument proving multiset equality between the
/// execution trace and the Twist sorted trace.
///
/// For random challenges τ, γ (from Fiat-Shamir after w1 commitment):
/// - Encodes each operation as `enc = addr + τ·val + τ²·is_write`
/// - Computes LogUp denominators `1/(γ - enc)` on both execution and sorted sides
/// - Constrains `Σ exec_denoms = Σ sorted_denoms` (multiset equality)
///
/// All denominator witnesses depend on τ, γ and end up in w2.
fn add_twist_permutation(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    twist_info: &TwistSchemeInfo,
    blocks: &[&MemoryBlock],
) {
    let w_one = r1cs_compiler.witness_one();

    // 2 Fiat-Shamir challenges for the permutation argument
    let tau = r1cs_compiler
        .add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let gamma = r1cs_compiler
        .add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let tau_sq = r1cs_compiler.add_product(tau, tau);

    let mut exec_inv_indices = Vec::new();
    let mut sorted_inv_indices = Vec::new();

    let mut addr_offset = 0usize;

    // --- Execution side ---
    // Encode each operation from the R1CS execution trace.
    for block in blocks {
        let memory_size = block.initial_value_witnesses.len();

        // Initial writes (timestamp 0, is_write = 1)
        for (local_addr, &init_val_w) in block.initial_value_witnesses.iter().enumerate() {
            let global_addr = FieldElement::from((local_addr + addr_offset) as u64);
            let tau_val = r1cs_compiler.add_product(tau, init_val_w);
            // enc = global_addr + τ·init_val + τ²  (is_write=1 → τ²·1 = τ²)
            let enc = r1cs_compiler.add_sum(vec![
                SumTerm(Some(global_addr), w_one),
                SumTerm(None, tau_val),
                SumTerm(None, tau_sq),
            ]);
            let inv = add_logup_inverse(r1cs_compiler, gamma, enc);
            exec_inv_indices.push(inv);
        }

        // Operations
        for op in &block.operations {
            match op {
                crate::memory::MemoryOperation::Load(addr_w, val_w) => {
                    // Read: is_write = 0, enc = (addr + offset) + τ·val
                    let tau_val = r1cs_compiler.add_product(tau, *val_w);
                    let enc = if addr_offset == 0 {
                        r1cs_compiler.add_sum(vec![
                            SumTerm(None, *addr_w),
                            SumTerm(None, tau_val),
                        ])
                    } else {
                        let offset_fe = FieldElement::from(addr_offset as u64);
                        r1cs_compiler.add_sum(vec![
                            SumTerm(None, *addr_w),
                            SumTerm(Some(offset_fe), w_one),
                            SumTerm(None, tau_val),
                        ])
                    };
                    let inv = add_logup_inverse(r1cs_compiler, gamma, enc);
                    exec_inv_indices.push(inv);
                }
                crate::memory::MemoryOperation::Store(addr_w, new_val_w) => {
                    // Write: is_write = 1, enc = (addr + offset) + τ·new_val + τ²
                    let tau_val = r1cs_compiler.add_product(tau, *new_val_w);
                    let enc = if addr_offset == 0 {
                        r1cs_compiler.add_sum(vec![
                            SumTerm(None, *addr_w),
                            SumTerm(None, tau_val),
                            SumTerm(None, tau_sq),
                        ])
                    } else {
                        let offset_fe = FieldElement::from(addr_offset as u64);
                        r1cs_compiler.add_sum(vec![
                            SumTerm(None, *addr_w),
                            SumTerm(Some(offset_fe), w_one),
                            SumTerm(None, tau_val),
                            SumTerm(None, tau_sq),
                        ])
                    };
                    let inv = add_logup_inverse(r1cs_compiler, gamma, enc);
                    exec_inv_indices.push(inv);
                }
            }
        }

        addr_offset += memory_size;
    }

    // --- Sorted trace side ---
    // Encode each position from the committed Twist polynomials.
    let total_trace: usize = blocks
        .iter()
        .map(|b| b.initial_value_witnesses.len() + b.operations.len())
        .sum();

    for j in 0..total_trace {
        let addr_w = twist_info.poly_start(4) + j; // addr polynomial
        let val_w = twist_info.poly_start(2) + j; // val polynomial
        let isw_w = twist_info.poly_start(1) + j; // is_write polynomial

        let tau_val = r1cs_compiler.add_product(tau, val_w);
        let tau_sq_isw = r1cs_compiler.add_product(tau_sq, isw_w);
        let enc = r1cs_compiler.add_sum(vec![
            SumTerm(None, addr_w),
            SumTerm(None, tau_val),
            SumTerm(None, tau_sq_isw),
        ]);
        let inv = add_logup_inverse(r1cs_compiler, gamma, enc);
        sorted_inv_indices.push(inv);
    }

    // --- Sum equality constraint ---
    // Σ exec_inv = Σ sorted_inv  ⟺  multiset equality (by Schwartz-Zippel)
    let exec_terms: Vec<SumTerm> = exec_inv_indices
        .iter()
        .map(|&idx| SumTerm(None, idx))
        .collect();
    let sorted_terms: Vec<SumTerm> = sorted_inv_indices
        .iter()
        .map(|&idx| SumTerm(None, idx))
        .collect();

    let total_exec = r1cs_compiler.add_sum(exec_terms);
    let total_sorted = r1cs_compiler.add_sum(sorted_terms);

    // total_exec * 1 = total_sorted
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), total_exec)],
        &[(FieldElement::one(), w_one)],
        &[(FieldElement::one(), total_sorted)],
    );

    debug!(
        exec_ops = exec_inv_indices.len(),
        sorted_ops = sorted_inv_indices.len(),
        "Added LogUp permutation argument for Twist"
    );
}

/// Allocate a LogUp inverse witness: `1/(γ - enc)`, with R1CS constraint
/// enforcing correctness.
fn add_logup_inverse(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    gamma: usize,
    enc: usize,
) -> usize {
    let w_one = r1cs_compiler.witness_one();

    // diff = γ - enc
    let diff = r1cs_compiler.add_sum(vec![
        SumTerm(None, gamma),
        SumTerm(Some(-FieldElement::one()), enc),
    ]);

    // inv = 1/diff (solver computes the inverse)
    let inv = r1cs_compiler
        .add_witness_builder(WitnessBuilder::SafeInverse(r1cs_compiler.num_witnesses(), diff));

    // R1CS: inv * diff = 1
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), inv)],
        &[(FieldElement::one(), diff)],
        &[(FieldElement::one(), w_one)],
    );

    inv
}
