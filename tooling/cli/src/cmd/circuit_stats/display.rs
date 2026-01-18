//! Display formatting for circuit statistics output.

use {
    super::{memory::describe_block_type, stats_collector::CircuitStats},
    acir::{circuit::Circuit, FieldElement},
    provekit_common::R1CS,
    provekit_r1cs_compiler::R1CSBreakdown,
    std::collections::HashMap,
};

const SEPARATOR: &str = "══════════════════════════════════════════════════════════════════════";
const SUBSECTION: &str = "─────────────────────────────────────────────";

pub(super) fn print_io_summary(circuit: &Circuit<FieldElement>) {
    println!("\n┌─ Circuit I/O Summary");
    println!("│  Private inputs:  {}", circuit.private_parameters.len());
    println!("│  Public inputs:   {}", circuit.public_parameters.0.len());
    println!("│  Return values:   {}", circuit.return_values.0.len());
    println!("│  ACIR witnesses:  {}", circuit.current_witness_index);
    println!("└{}", SUBSECTION);
}

pub(super) fn print_acir_stats(stats: &CircuitStats) {
    print_assert_zero_stats(stats);
    print_blackbox_stats(stats);
    print_range_check_stats(stats);
    print_and_xor_stats(stats);
    print_memory_stats(stats);
    print_call_stats(stats);
}

fn print_assert_zero_stats(stats: &CircuitStats) {
    println!("\n┌─ AssertZero Constraints");
    println!("│  Opcodes:             {}", stats.num_assert_zero_opcodes);
    println!("│  Multiplication terms: {}", stats.num_mul_terms);
    println!("└{}", SUBSECTION);
}

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

    let components = collect_r1cs_components(stats, circuit, breakdown);
    for component in &components {
        println!("{}", component);
    }

    if !combined_range_checks.is_empty() {
        print_range_check_details(&combined_range_checks);
    }

    print_batched_operations(stats, breakdown);
    print_r1cs_totals(r1cs, breakdown);
}

fn collect_r1cs_components(
    stats: &CircuitStats,
    circuit: &Circuit<FieldElement>,
    breakdown: &R1CSBreakdown,
) -> Vec<String> {
    let mut components = Vec::new();

    let base_witnesses = (circuit.current_witness_index as usize) + 1;
    components.push(format!(
        "Base witnesses:                      {:>8} witnesses  (ACIR + constant)",
        base_witnesses
    ));

    if stats.num_assert_zero_opcodes > 0 || breakdown.assert_zero_constraints > 0 {
        components.push(format!(
            "AssertZero ({} opcodes):             {:>8} constraints {:>8} witnesses",
            stats.num_assert_zero_opcodes,
            breakdown.assert_zero_constraints,
            breakdown.assert_zero_witnesses
        ));
    }

    if let Some(&count) = stats.blackbox_func_counts.get("Sha256Compression") {
        if count > 0 {
            components.push(format!(
                "SHA256 Direct ({} calls):            {:>8} constraints {:>8} witnesses",
                count, breakdown.sha256_direct_constraints, breakdown.sha256_direct_witnesses
            ));
        }
    }

    if let Some(&count) = stats.blackbox_func_counts.get("Poseidon2Permutation") {
        if count > 0 {
            components.push(format!(
                "Poseidon2 Permutation ({} calls):    {:>8} constraints {:>8} witnesses",
                count, breakdown.poseidon2_constraints, breakdown.poseidon2_witnesses
            ));
        }
    }

    if breakdown.memory_rom_constraints > 0 {
        components.push(format!(
            "Memory ROM ({} blocks):              {:>8} constraints {:>8} witnesses",
            stats.memory.read_only_block_count(),
            breakdown.memory_rom_constraints,
            breakdown.memory_rom_witnesses
        ));
    }
    if breakdown.memory_ram_constraints > 0 {
        let ram_blocks = stats.memory.total_blocks() - stats.memory.read_only_block_count();
        components.push(format!(
            "Memory RAM ({} blocks):              {:>8} constraints {:>8} witnesses",
            ram_blocks, breakdown.memory_ram_constraints, breakdown.memory_ram_witnesses
        ));
    }

    components
}

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

fn print_batched_operations(stats: &CircuitStats, breakdown: &R1CSBreakdown) {
    let and_count = *stats.blackbox_func_counts.get("AND").unwrap_or(&0);
    let xor_count = *stats.blackbox_func_counts.get("XOR").unwrap_or(&0);
    let range_count = *stats.blackbox_func_counts.get("RANGE").unwrap_or(&0);
    let sha256_count = *stats
        .blackbox_func_counts
        .get("Sha256Compression")
        .unwrap_or(&0);

    if and_count == 0
        && xor_count == 0
        && range_count == 0
        && breakdown.sha256_and_ops == 0
        && breakdown.sha256_xor_ops == 0
    {
        return;
    }

    let total_batched_constraints = breakdown.binop_constraints + breakdown.range_constraints;
    let total_batched_witnesses = breakdown.binop_witnesses + breakdown.range_witnesses;

    println!("\n┌─ Batched Operations (Exact Breakdown)");

    let total_binop_ops = breakdown.and_ops_total + breakdown.xor_ops_total;
    let sha256_binop_ops = breakdown.sha256_and_ops + breakdown.sha256_xor_ops;
    if total_binop_ops > 0 || breakdown.binop_constraints > 0 || breakdown.binop_witnesses > 0 {
        println!(
            "│  BINOP ({} AND + {} XOR, {} from SHA256): {:>8} constraints {:>8} witnesses",
            and_count,
            xor_count,
            sha256_binop_ops,
            breakdown.binop_constraints,
            breakdown.binop_witnesses
        );
    }

    if range_count > 0 || breakdown.range_constraints > 0 || breakdown.range_witnesses > 0 {
        let non_sha256_range = breakdown
            .range_ops_total
            .saturating_sub(breakdown.sha256_range_ops);
        println!(
            "│  RANGE ({} non-SHA256, {} from SHA256): {:>8} constraints {:>8} witnesses",
            non_sha256_range,
            breakdown.sha256_range_ops,
            breakdown.range_constraints,
            breakdown.range_witnesses
        );
        if sha256_count > 0 && breakdown.sha256_range_ops > 0 {
            let per_sha256 = breakdown.sha256_range_ops / sha256_count;
            println!("│         (~{} range checks per SHA256 call)", per_sha256);
        }
    }

    println!("│");
    println!(
        "│  Total batched:       {:>8} constraints {:>8} witnesses",
        total_batched_constraints, total_batched_witnesses
    );
    println!("└{}", SUBSECTION);

    if sha256_count > 0 {
        let sha256_direct = breakdown.sha256_direct_constraints;
        let sha256_direct_w = breakdown.sha256_direct_witnesses;

        // Combined binop attribution for SHA256
        let total_binop_ops = breakdown.and_ops_total + breakdown.xor_ops_total;
        let sha256_binop_ops = breakdown.sha256_and_ops + breakdown.sha256_xor_ops;
        let sha256_binop_constraints = if total_binop_ops > 0 {
            (breakdown.binop_constraints * sha256_binop_ops) / total_binop_ops
        } else {
            0
        };
        let sha256_binop_witnesses = if total_binop_ops > 0 {
            (breakdown.binop_witnesses * sha256_binop_ops) / total_binop_ops
        } else {
            0
        };

        let sha256_range_constraints = if breakdown.range_ops_total > 0 {
            (breakdown.range_constraints * breakdown.sha256_range_ops) / breakdown.range_ops_total
        } else {
            0
        };
        let sha256_range_witnesses = if breakdown.range_ops_total > 0 {
            (breakdown.range_witnesses * breakdown.sha256_range_ops) / breakdown.range_ops_total
        } else {
            0
        };

        let sha256_batched_constraints = sha256_binop_constraints + sha256_range_constraints;
        let sha256_batched_witnesses = sha256_binop_witnesses + sha256_range_witnesses;

        let sha256_total_constraints = sha256_direct + sha256_batched_constraints;
        let sha256_total_witnesses = sha256_direct_w + sha256_batched_witnesses;
        let per_sha256 = sha256_total_constraints / sha256_count;
        let per_sha256_w = sha256_total_witnesses / sha256_count;

        println!("\n┌─ SHA256 Total Cost Summary");
        println!(
            "│  Direct:              {:>8} constraints {:>8} witnesses",
            sha256_direct, sha256_direct_w
        );
        println!(
            "│  Batched (BINOP):     {:>8} constraints {:>8} witnesses ({}/{} ops)",
            sha256_binop_constraints, sha256_binop_witnesses, sha256_binop_ops, total_binop_ops
        );
        println!(
            "│  Batched (RANGE):     {:>8} constraints {:>8} witnesses ({}/{} ops)",
            sha256_range_constraints,
            sha256_range_witnesses,
            breakdown.sha256_range_ops,
            breakdown.range_ops_total
        );
        println!("│  ─────────────────────────────────────────────────────────────");
        println!(
            "│  Total SHA256:        {:>8} constraints {:>8} witnesses ({} calls)",
            sha256_total_constraints, sha256_total_witnesses, sha256_count
        );
        println!(
            "│  Per compression:     {:>8} constraints {:>8} witnesses",
            per_sha256, per_sha256_w
        );
        println!("└{}", SUBSECTION);
    }
}

fn print_r1cs_totals(r1cs: &R1CS, breakdown: &R1CSBreakdown) {
    let total_tracked_constraints = breakdown.assert_zero_constraints
        + breakdown.memory_rom_constraints
        + breakdown.memory_ram_constraints
        + breakdown.sha256_direct_constraints
        + breakdown.poseidon2_constraints
        + breakdown.binop_constraints
        + breakdown.range_constraints;

    let total_tracked_witnesses = breakdown.assert_zero_witnesses
        + breakdown.memory_rom_witnesses
        + breakdown.memory_ram_witnesses
        + breakdown.sha256_direct_witnesses
        + breakdown.poseidon2_witnesses
        + breakdown.binop_witnesses
        + breakdown.range_witnesses;

    println!("\n{}", SEPARATOR);
    println!(
        "TRACKED CONSTRAINTS: {:>8}  (sum of breakdown)",
        total_tracked_constraints
    );
    println!(
        "TRACKED WITNESSES:   {:>8}  (sum of breakdown, excludes base)",
        total_tracked_witnesses
    );
    println!("{}", SEPARATOR);
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

    if total_tracked_constraints != r1cs.num_constraints() {
        println!(
            "UNTRACKED CONSTRAINTS: {:>8}",
            r1cs.num_constraints()
                .saturating_sub(total_tracked_constraints)
        );
    }

    println!(
        "\nR1CS Matrix Sparsity: A = {} entries, B = {} entries, C = {} entries",
        r1cs.a.num_entries(),
        r1cs.b.num_entries(),
        r1cs.c.num_entries()
    );
    println!();
}
