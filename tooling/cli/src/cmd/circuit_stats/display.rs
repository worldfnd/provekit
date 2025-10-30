//! Formatted output for circuit statistics.
//!
//! Provides clean, professional display of all collected statistics.

use {
    super::{
        memory::{describe_block_type, MemoryAggregation},
        stats_collector::{
            CircuitStats, POSEIDON2_PERMUTATION_CONSTRAINTS, POSEIDON2_PERMUTATION_WITNESSES,
            SHA256_COMPRESSION_CONSTRAINTS, SHA256_COMPRESSION_WITNESSES,
        },
    },
    acir::{circuit::Circuit, FieldElement},
    provekit_common::R1CS,
    provekit_r1cs_compiler::R1CSBreakdown,
    std::collections::HashMap,
};

const SEPARATOR: &str = "══════════════════════════════════════════════════════════════════════";
const SUBSECTION: &str = "─────────────────────────────────────────────";

/// Prints circuit input/output summary.
pub(super) fn print_io_summary(circuit: &Circuit<FieldElement>) {
    println!("\n┌─ Circuit I/O Summary");
    println!("│  Private inputs:  {}", circuit.private_parameters.len());
    println!("│  Public inputs:   {}", circuit.public_parameters.0.len());
    println!("│  Return values:   {}", circuit.return_values.0.len());
    println!("│  ACIR witnesses:  {}", circuit.current_witness_index);
    println!("└{}", SUBSECTION);
}

/// Prints all ACIR-level statistics.
pub(super) fn print_acir_stats(stats: &CircuitStats) {
    print_assert_zero_stats(stats);
    print_blackbox_stats(stats);
    print_range_check_stats(stats);
    print_and_xor_stats(stats);
    print_memory_stats(stats);
    print_call_stats(stats);
}

/// Prints AssertZero constraint statistics.
fn print_assert_zero_stats(stats: &CircuitStats) {
    println!("\n┌─ AssertZero Constraints");
    println!("│  Opcodes:             {}", stats.num_assert_zero_opcodes);
    println!("│  Multiplication terms: {}", stats.num_mul_terms);
    println!("└{}", SUBSECTION);
}

/// Prints black box function usage.
fn print_blackbox_stats(stats: &CircuitStats) {
    let mut sorted_funcs: Vec<_> = stats.blackbox_func_counts.iter().collect();
    sorted_funcs.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let active_funcs: Vec<_> = sorted_funcs
        .into_iter()
        .filter(|(_, &count)| count > 0)
        .collect();

    if active_funcs.is_empty() {
        return;
    }

    println!("\n┌─ Black Box Functions");
    for (func_name, count) in active_funcs {
        println!("│  {:<24} {:>8}", format!("{}:", func_name), count);
    }
    println!("└{}", SUBSECTION);
}

/// Prints range check statistics.
fn print_range_check_stats(stats: &CircuitStats) {
    if stats.range_check_bit_counts.is_empty() {
        return;
    }

    let mut sorted_checks: Vec<_> = stats.range_check_bit_counts.iter().collect();
    sorted_checks.sort_by(|a, b| b.1.cmp(a.1));

    println!("\n┌─ Range Checks");
    for (num_bits, count) in sorted_checks {
        println!("│  {:>3}-bit: {:>8}", num_bits, count);
    }
    println!("└{}", SUBSECTION);
}

/// Prints AND/XOR operation details.
fn print_and_xor_stats(stats: &CircuitStats) {
    if !stats.and_bit_counts.is_empty() {
        println!("\n┌─ AND Operations");
        for ((lhs_bits, rhs_bits), count) in &stats.and_bit_counts {
            println!(
                "│  ({:2}, {:2}) bits: {:>8} occurrences",
                lhs_bits, rhs_bits, count
            );
        }
        println!("│  Input types:");
        println!(
            "│    Constant & Constant: {}",
            stats.homogeneous_constant_and_inputs
        );
        println!(
            "│    Witness & Constant:  {}",
            stats.heterogeneous_and_inputs
        );
        println!(
            "│    Witness & Witness:   {}",
            stats.homogeneous_witness_and_inputs
        );
        println!("└{}", SUBSECTION);
    }

    if !stats.xor_bit_counts.is_empty() {
        println!("\n┌─ XOR Operations");
        for ((lhs_bits, rhs_bits), count) in &stats.xor_bit_counts {
            println!(
                "│  ({:2}, {:2}) bits: {:>8} occurrences",
                lhs_bits, rhs_bits, count
            );
        }
        println!(
            "│  Has constant inputs: {}",
            stats.xor_with_non_witness_value
        );
        println!("│  Input types:");
        println!(
            "│    Constant & Constant: {}",
            stats.homogeneous_constant_xor_inputs
        );
        println!(
            "│    Witness & Constant:  {}",
            stats.heterogeneous_xor_inputs
        );
        println!(
            "│    Witness & Witness:   {}",
            stats.homogeneous_witness_xor_inputs
        );
        println!("└{}", SUBSECTION);
    }
}

/// Prints memory operation statistics.
fn print_memory_stats(stats: &CircuitStats) {
    if stats.memory.total_blocks() == 0 {
        return;
    }

    let memory_summary = stats.memory.aggregate();
    let read_only_blocks = stats.memory.read_only_block_count();
    let read_write_blocks = stats.memory.total_blocks().saturating_sub(read_only_blocks);

    println!("\n┌─ Memory Operations");
    println!("│  Total blocks:    {}", stats.memory.total_blocks());
    println!("│  Allocated words: {}", stats.memory.total_allocated());
    println!("│  Read operations: {}", stats.memory.total_reads());
    println!("│  Write operations: {}", stats.memory.total_writes());
    println!("│  ROM blocks:      {}", read_only_blocks);
    println!("│  RAM blocks:      {}", read_write_blocks);

    if !memory_summary.blocks_with_write_after_read.is_empty() {
        println!(
            "│  Blocks with write-after-read: {:?}",
            memory_summary.blocks_with_write_after_read
        );
    }

    println!("│");
    println!("│  Per-block details:");
    for (block_id, block) in stats.memory.block_summaries() {
        let block_type = block
            .block_type
            .as_ref()
            .map(describe_block_type)
            .unwrap_or_else(|| "Unknown".to_string());
        println!(
            "│    Block {:>3}: {:<12} size {:>4} │ reads {:>4} │ writes {:>4}",
            block_id, block_type, block.initial_size, block.reads, block.writes
        );
    }

    if !memory_summary.range_checks.is_empty() {
        println!("│");
        println!("│  RAM range checks:");
        let mut checks: Vec<_> = memory_summary.range_checks.iter().collect();
        checks.sort_by(|a, b| b.1.cmp(a.1));
        for (bits, count) in checks {
            println!("│    {:>3}-bit: {:>8}", bits, count);
        }
    }

    println!("└{}", SUBSECTION);
}

/// Prints function call statistics.
fn print_call_stats(stats: &CircuitStats) {
    if stats.num_brillig_calls == 0 && stats.num_calls == 0 {
        return;
    }

    println!("\n┌─ Function Calls");
    if stats.num_brillig_calls > 0 {
        println!(
            "│  Brillig (unconstrained): {} calls ({} unique)",
            stats.num_brillig_calls,
            stats.unique_brillig_calls.len()
        );
    }
    if stats.num_calls > 0 {
        println!(
            "│  Circuit calls:           {} calls ({} unique)",
            stats.num_calls,
            stats.unique_calls.len()
        );
    }
    println!("└{}", SUBSECTION);
}

/// Prints comprehensive R1CS complexity breakdown.
pub(super) fn print_r1cs_breakdown(
    stats: &CircuitStats,
    circuit: &Circuit<FieldElement>,
    r1cs: &R1CS,
    breakdown: &R1CSBreakdown,
) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                R1CS Complexity Breakdown                      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");

    let memory_summary = stats.memory.aggregate();
    let mut combined_range_checks = stats.range_check_bit_counts.clone();
    for (bits, count) in &memory_summary.range_checks {
        *combined_range_checks.entry(*bits).or_insert(0) += *count;
    }

    // Collect component costs
    let components = collect_r1cs_components(stats, circuit, &memory_summary);

    // Print each component
    for component in &components {
        println!("{}", component);
    }

    // Print range check details if present
    if !combined_range_checks.is_empty() {
        print_range_check_details(&combined_range_checks);
    }

    // Print batched operations section
    print_batched_operations(stats, breakdown);

    // Print totals and matrix info
    print_r1cs_totals(r1cs);
}

/// Collects all R1CS component costs for display.
fn collect_r1cs_components(
    stats: &CircuitStats,
    circuit: &Circuit<FieldElement>,
    memory_summary: &MemoryAggregation,
) -> Vec<String> {
    let mut components = Vec::new();

    // Base witnesses
    let base_witnesses = (circuit.current_witness_index as usize) + 1;
    components.push(format!(
        "Base witnesses:                      {:>8} witnesses  (ACIR + constant)",
        base_witnesses
    ));

    // AssertZero
    if stats.num_assert_zero_opcodes > 0 {
        let constraints = stats.num_mul_terms;
        let witnesses = stats
            .num_mul_terms
            .saturating_sub(stats.num_assert_zero_opcodes);
        components.push(format!(
            "AssertZero ({} opcodes):             {:>8} constraints {:>8} witnesses",
            stats.num_assert_zero_opcodes, constraints, witnesses
        ));
    }

    // SHA256
    if let Some(&count) = stats.blackbox_func_counts.get("Sha256Compression") {
        if count > 0 {
            let constraints = SHA256_COMPRESSION_CONSTRAINTS * count;
            let witnesses = SHA256_COMPRESSION_WITNESSES * count;
            components.push(format!(
                "SHA256 Compression ({} calls):       {:>8} constraints {:>8} witnesses",
                count, constraints, witnesses
            ));
        }
    }

    // Poseidon2
    if let Some(&count) = stats.blackbox_func_counts.get("Poseidon2Permutation") {
        if count > 0 {
            let constraints = POSEIDON2_PERMUTATION_CONSTRAINTS * count;
            let witnesses = POSEIDON2_PERMUTATION_WITNESSES * count;
            components.push(format!(
                "Poseidon2 Permutation ({} calls):    {:>8} constraints {:>8} witnesses",
                count, constraints, witnesses
            ));
        }
    }

    // Memory
    if memory_summary.rom_constraints > 0 {
        components.push(format!(
            "Memory ROM ({} blocks):              {:>8} constraints {:>8} witnesses",
            stats.memory.read_only_block_count(),
            memory_summary.rom_constraints,
            memory_summary.rom_witnesses
        ));
    }
    if memory_summary.ram_constraints > 0 {
        let ram_blocks = stats.memory.total_blocks() - stats.memory.read_only_block_count();
        components.push(format!(
            "Memory RAM ({} blocks):              {:>8} constraints {:>8} witnesses",
            ram_blocks, memory_summary.ram_constraints, memory_summary.ram_witnesses
        ));
    }

    components
}

/// Prints detailed range check breakdown.
fn print_range_check_details(range_checks: &HashMap<u32, usize>) {
    println!("\n┌─ Range Check Details");
    let mut sorted: Vec<_> = range_checks.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (bits, count) in sorted.iter().take(10) {
        println!("│  {:>3}-bit: {:>8} checks", bits, count);
    }
    if sorted.len() > 10 {
        println!("│  ... and {} more bit-widths", sorted.len() - 10);
    }
    println!("└{}", SUBSECTION);
}

/// Prints batched operations cost (AND/XOR/RANGE) with exact breakdown.
fn print_batched_operations(stats: &CircuitStats, breakdown: &R1CSBreakdown) {
    let and_count = *stats.blackbox_func_counts.get("AND").unwrap_or(&0);
    let xor_count = *stats.blackbox_func_counts.get("XOR").unwrap_or(&0);
    let range_count = *stats.blackbox_func_counts.get("RANGE").unwrap_or(&0);

    if and_count == 0 && xor_count == 0 && range_count == 0 {
        return;
    }

    let total_batched_constraints =
        breakdown.and_constraints + breakdown.xor_constraints + breakdown.range_constraints;
    let total_batched_witnesses =
        breakdown.and_witnesses + breakdown.xor_witnesses + breakdown.range_witnesses;

    println!("\n┌─ Batched Operations (Exact Breakdown)");

    if and_count > 0 || breakdown.and_constraints > 0 || breakdown.and_witnesses > 0 {
        println!(
            "│  AND ({} ops):        {:>8} constraints {:>8} witnesses",
            and_count, breakdown.and_constraints, breakdown.and_witnesses
        );
    }

    if xor_count > 0 || breakdown.xor_constraints > 0 || breakdown.xor_witnesses > 0 {
        println!(
            "│  XOR ({} ops):        {:>8} constraints {:>8} witnesses",
            xor_count, breakdown.xor_constraints, breakdown.xor_witnesses
        );
    }

    if range_count > 0 || breakdown.range_constraints > 0 || breakdown.range_witnesses > 0 {
        println!(
            "│  RANGE ({} ops):      {:>8} constraints {:>8} witnesses",
            range_count, breakdown.range_constraints, breakdown.range_witnesses
        );
    }

    println!("│");
    println!(
        "│  Total batched:       {:>8} constraints {:>8} witnesses",
        total_batched_constraints, total_batched_witnesses
    );
    println!("│  (includes digital decomposition, lookup tables, challenges, inverses)");
    println!("└{}", SUBSECTION);
}

/// Prints final R1CS totals and matrix information.
fn print_r1cs_totals(r1cs: &R1CS) {
    println!("\n{}", SEPARATOR);
    println!(
        "TOTAL CONSTRAINTS:   {:>8}  (2^{:.2})",
        r1cs.num_constraints(),
        (r1cs.num_constraints() as f64).log2()
    );
    println!(
        "TOTAL WITNESSES:     {:>8}  (2^{:.2})",
        r1cs.num_witnesses(),
        (r1cs.num_witnesses() as f64).log2()
    );
    println!("{}", SEPARATOR);
    println!(
        "\nR1CS Matrix Sparsity: A = {} entries, B = {} entries, C = {} entries",
        r1cs.a.num_entries(),
        r1cs.b.num_entries(),
        r1cs.c.num_entries()
    );
    println!();
}
