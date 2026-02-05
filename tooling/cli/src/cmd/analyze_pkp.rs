use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, Prover},
    std::path::PathBuf,
    tracing::instrument,
};

/// Analyze the size breakdown of a PKP file
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "analyze-pkp")]
pub struct Args {
    /// path to the PKP file
    #[argh(positional)]
    pkp_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let prover: Prover = read(&self.pkp_path).context("while reading PKP file")?;

        let program_size = postcard::to_allocvec(&prover.program)
            .map(|v| v.len())
            .unwrap_or(0);
        let r1cs_size = postcard::to_allocvec(&prover.r1cs)
            .map(|v| v.len())
            .unwrap_or(0);
        let split_witness_builders_size = postcard::to_allocvec(&prover.split_witness_builders)
            .map(|v| v.len())
            .unwrap_or(0);
        let witness_generator_size = postcard::to_allocvec(&prover.witness_generator)
            .map(|v| v.len())
            .unwrap_or(0);
        let whir_for_witness_size = postcard::to_allocvec(&prover.whir_for_witness)
            .map(|v| v.len())
            .unwrap_or(0);

        let total_size = postcard::to_allocvec(&prover).map(|v| v.len()).unwrap_or(0);

        println!("PKP Size Analysis:");
        println!("==================");
        println!();
        println!("Component breakdown (uncompressed Postcard):");
        println!(
            "  Program (ACIR):           {:>12} bytes ({:>5.1}%)",
            program_size,
            program_size as f64 / total_size as f64 * 100.0
        );
        println!(
            "  R1CS:                     {:>12} bytes ({:>5.1}%)",
            r1cs_size,
            r1cs_size as f64 / total_size as f64 * 100.0
        );
        println!(
            "  SplitWitnessBuilders:     {:>12} bytes ({:>5.1}%)",
            split_witness_builders_size,
            split_witness_builders_size as f64 / total_size as f64 * 100.0
        );
        println!(
            "  NoirWitnessGenerator:     {:>12} bytes ({:>5.1}%)",
            witness_generator_size,
            witness_generator_size as f64 / total_size as f64 * 100.0
        );
        println!(
            "  WhirR1CSScheme:           {:>12} bytes ({:>5.1}%)",
            whir_for_witness_size,
            whir_for_witness_size as f64 / total_size as f64 * 100.0
        );
        println!("  ------------------------------------------");
        println!("  Total:                    {:>12} bytes", total_size);
        println!();

        let interner_size = postcard::to_allocvec(&prover.r1cs.interner)
            .map(|v| v.len())
            .unwrap_or(0);
        let matrix_a_size = postcard::to_allocvec(&prover.r1cs.a)
            .map(|v| v.len())
            .unwrap_or(0);
        let matrix_b_size = postcard::to_allocvec(&prover.r1cs.b)
            .map(|v| v.len())
            .unwrap_or(0);
        let matrix_c_size = postcard::to_allocvec(&prover.r1cs.c)
            .map(|v| v.len())
            .unwrap_or(0);

        println!("R1CS breakdown:");
        println!(
            "  Interner:                 {:>12} bytes ({:>5.1}% of R1CS)",
            interner_size,
            interner_size as f64 / r1cs_size as f64 * 100.0
        );
        println!(
            "  Matrix A:                 {:>12} bytes ({:>5.1}% of R1CS)",
            matrix_a_size,
            matrix_a_size as f64 / r1cs_size as f64 * 100.0
        );
        println!(
            "  Matrix B:                 {:>12} bytes ({:>5.1}% of R1CS)",
            matrix_b_size,
            matrix_b_size as f64 / r1cs_size as f64 * 100.0
        );
        println!(
            "  Matrix C:                 {:>12} bytes ({:>5.1}% of R1CS)",
            matrix_c_size,
            matrix_c_size as f64 / r1cs_size as f64 * 100.0
        );
        println!();

        let stats_a = prover.r1cs.a.delta_encoding_stats();
        let stats_b = prover.r1cs.b.delta_encoding_stats();
        let stats_c = prover.r1cs.c.delta_encoding_stats();

        let total_absolute =
            stats_a.absolute_bytes + stats_b.absolute_bytes + stats_c.absolute_bytes;
        let total_delta = stats_a.delta_bytes + stats_b.delta_bytes + stats_c.delta_bytes;
        let total_savings = total_absolute.saturating_sub(total_delta);

        println!("Delta encoding savings (column indices):");
        println!(
            "  Matrix A:                 {:>12} bytes saved ({:>5.1}%)",
            stats_a.savings_bytes(),
            stats_a.savings_percent()
        );
        println!(
            "  Matrix B:                 {:>12} bytes saved ({:>5.1}%)",
            stats_b.savings_bytes(),
            stats_b.savings_percent()
        );
        println!(
            "  Matrix C:                 {:>12} bytes saved ({:>5.1}%)",
            stats_c.savings_bytes(),
            stats_c.savings_percent()
        );
        println!(
            "  Total:                    {:>12} bytes saved ({:>5.1}%)",
            total_savings,
            if total_absolute > 0 {
                total_savings as f64 / total_absolute as f64 * 100.0
            } else {
                0.0
            }
        );
        println!();

        let w1_layers_size = postcard::to_allocvec(&prover.split_witness_builders.w1_layers)
            .map(|v| v.len())
            .unwrap_or(0);
        let w2_layers_size = postcard::to_allocvec(&prover.split_witness_builders.w2_layers)
            .map(|v| v.len())
            .unwrap_or(0);

        println!("SplitWitnessBuilders breakdown:");
        println!(
            "  W1 Layers:                {:>12} bytes ({:>5.1}% of SWB)",
            w1_layers_size,
            w1_layers_size as f64 / split_witness_builders_size as f64 * 100.0
        );
        println!(
            "  W2 Layers:                {:>12} bytes ({:>5.1}% of SWB)",
            w2_layers_size,
            w2_layers_size as f64 / split_witness_builders_size as f64 * 100.0
        );
        println!();

        println!("Circuit statistics:");
        println!(
            "  Constraints:              {:>12}",
            prover.r1cs.num_constraints()
        );
        println!(
            "  Witnesses:                {:>12}",
            prover.r1cs.num_witnesses()
        );
        println!(
            "  Public inputs:            {:>12}",
            prover.r1cs.num_public_inputs
        );
        println!();

        let bytes_per_constraint = total_size as f64 / prover.r1cs.num_constraints() as f64;
        println!(
            "Efficiency: {:.2} bytes/constraint (uncompressed)",
            bytes_per_constraint
        );
        println!();

        print_witness_builder_stats(&prover.split_witness_builders);

        Ok(())
    }
}

use {
    provekit_common::witness::{LayeredWitnessBuilders, SplitWitnessBuilders, WitnessBuilder},
    std::collections::HashMap,
};

fn builder_size(builder: &WitnessBuilder) -> usize {
    postcard::to_allocvec(builder).map(|v| v.len()).unwrap_or(0)
}

fn collect_sizes(layers: &LayeredWitnessBuilders) -> HashMap<&'static str, (usize, usize)> {
    let mut stats: HashMap<&'static str, (usize, usize)> = HashMap::new();
    for layer in &layers.layers {
        for builder in &layer.witness_builders {
            let name = match builder {
                WitnessBuilder::Constant(_) => "Constant",
                WitnessBuilder::Acir(..) => "Acir",
                WitnessBuilder::Sum(..) => "Sum",
                WitnessBuilder::Product(..) => "Product",
                WitnessBuilder::MultiplicitiesForRange(..) => "MultiplicitiesForRange",
                WitnessBuilder::Challenge(_) => "Challenge",
                WitnessBuilder::IndexedLogUpDenominator(..) => "IndexedLogUpDenominator",
                WitnessBuilder::Inverse(..) => "Inverse",
                WitnessBuilder::ProductLinearOperation(..) => "ProductLinearOperation",
                WitnessBuilder::LogUpDenominator(..) => "LogUpDenominator",
                WitnessBuilder::LogUpInverse(..) => "LogUpInverse",
                WitnessBuilder::DigitalDecomposition(_) => "DigitalDecomposition",
                WitnessBuilder::SpiceMultisetFactor(..) => "SpiceMultisetFactor",
                WitnessBuilder::BytePartition { .. } => "BytePartition",
                WitnessBuilder::SpiceWitnesses(_) => "SpiceWitnesses",
                WitnessBuilder::BinOpLookupDenominator(..) => "BinOpLookupDenominator",
                WitnessBuilder::CombinedBinOpLookupDenominator(..) => {
                    "CombinedBinOpLookupDenominator"
                }
                WitnessBuilder::MultiplicitiesForBinOp(..) => "MultiplicitiesForBinOp",
                WitnessBuilder::U32Addition(..) => "U32Addition",
                WitnessBuilder::U32AdditionMulti(..) => "U32AdditionMulti",
                WitnessBuilder::And(..) => "And",
                WitnessBuilder::Xor(..) => "Xor",
                WitnessBuilder::CombinedTableEntryInverse(_) => "CombinedTableEntryInverse",
            };
            let size = builder_size(builder);
            let entry = stats.entry(name).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += size;
        }
    }
    stats
}

fn print_witness_builder_stats(swb: &SplitWitnessBuilders) {
    println!("WitnessBuilder variant distribution:");

    let w1_stats = collect_sizes(&swb.w1_layers);
    let w2_stats = collect_sizes(&swb.w2_layers);

    let mut all_names: Vec<&'static str> = w1_stats.keys().copied().collect();
    for name in w2_stats.keys() {
        if !all_names.contains(name) {
            all_names.push(name);
        }
    }
    all_names.sort();

    println!(
        "  {:35} {:>8} {:>10} {:>8} {:>10} {:>6}",
        "Variant", "W1 #", "W1 bytes", "W2 #", "W2 bytes", "avg"
    );
    println!(
        "  {:35} {:>8} {:>10} {:>8} {:>10} {:>6}",
        "-------", "----", "--------", "----", "--------", "---"
    );

    let mut total_w1_bytes = 0usize;
    let mut total_w2_bytes = 0usize;

    for name in all_names {
        let (w1_count, w1_bytes) = w1_stats.get(name).copied().unwrap_or((0, 0));
        let (w2_count, w2_bytes) = w2_stats.get(name).copied().unwrap_or((0, 0));
        if w1_count > 0 || w2_count > 0 {
            let total_count = w1_count + w2_count;
            let total_bytes = w1_bytes + w2_bytes;
            let avg = if total_count > 0 {
                total_bytes / total_count
            } else {
                0
            };
            println!(
                "  {:35} {:>8} {:>10} {:>8} {:>10} {:>6}",
                name, w1_count, w1_bytes, w2_count, w2_bytes, avg
            );
            total_w1_bytes += w1_bytes;
            total_w2_bytes += w2_bytes;
        }
    }

    println!(
        "  {:35} {:>8} {:>10} {:>8} {:>10}",
        "TOTAL", "", total_w1_bytes, "", total_w2_bytes
    );

    println!();
    println!("FieldElement deduplication analysis:");
    let (unique, total) = count_field_elements(&swb.w1_layers, &swb.w2_layers);
    println!("  Total FieldElements in WitnessBuilders: {}", total);
    println!("  Unique FieldElements: {}", unique);
    println!(
        "  Potential savings from interning: {} bytes ({:.1}%)",
        (total - unique) * 32,
        (total - unique) as f64 / total as f64 * 100.0
    );

    println!();
    println!("Note: XZ compression already deduplicates repeated FieldElements.");
    println!("Interning would primarily improve deserialization speed and memory.");
}

use {provekit_common::FieldElement as FE, std::collections::HashSet};

fn extract_field_elements(builder: &WitnessBuilder, elements: &mut Vec<FE>) {
    match builder {
        WitnessBuilder::Constant(ct) => elements.push(ct.1),
        WitnessBuilder::Sum(_, terms) => {
            for term in terms {
                if let Some(coeff) = term.0 {
                    elements.push(coeff);
                }
            }
        }
        WitnessBuilder::ProductLinearOperation(_, t1, t2) => {
            elements.push(t1.1);
            elements.push(t1.2);
            elements.push(t2.1);
            elements.push(t2.2);
        }
        WitnessBuilder::LogUpDenominator(_, _, wc) => elements.push(wc.0),
        WitnessBuilder::LogUpInverse(_, _, wc) => elements.push(wc.0),
        WitnessBuilder::IndexedLogUpDenominator(_, _, wc, ..) => elements.push(wc.0),
        WitnessBuilder::CombinedTableEntryInverse(data) => {
            elements.push(data.lhs);
            elements.push(data.rhs);
            elements.push(data.and_out);
            elements.push(data.xor_out);
        }
        WitnessBuilder::DigitalDecomposition(_) => {}
        WitnessBuilder::SpiceMultisetFactor(_, _, _, wc1, _, wc2) => {
            elements.push(wc1.0);
            elements.push(wc2.0);
        }
        _ => {}
    }
}

fn count_field_elements(
    w1: &LayeredWitnessBuilders,
    w2: &LayeredWitnessBuilders,
) -> (usize, usize) {
    let mut all_elements = Vec::new();

    for layer in &w1.layers {
        for builder in &layer.witness_builders {
            extract_field_elements(builder, &mut all_elements);
        }
    }
    for layer in &w2.layers {
        for builder in &layer.witness_builders {
            extract_field_elements(builder, &mut all_elements);
        }
    }

    let total = all_elements.len();
    let unique_set: HashSet<_> = all_elements.iter().collect();
    let unique = unique_set.len();

    (unique, total)
}
