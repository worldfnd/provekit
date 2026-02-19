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

        // let program_size = postcard::to_allocvec(&prover.program)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // let r1cs_size = postcard::to_allocvec(&prover.r1cs)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // #[cfg(not(feature = "mavros_compiler"))]
        // let split_witness_builders_size = postcard::to_allocvec(&prover.split_witness_builders)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // #[cfg(not(feature = "mavros_compiler"))]
        // let witness_generator_size = postcard::to_allocvec(&prover.witness_generator)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // let whir_for_witness_size = postcard::to_allocvec(&prover.whir_for_witness)
        //     .map(|v| v.len())
        //     .unwrap_or(0);

        // let total_size = postcard::to_allocvec(&prover).map(|v| v.len()).unwrap_or(0);

        // println!("PKP Size Analysis:");
        // println!("==================");
        // println!();
        // println!("Component breakdown (uncompressed Postcard):");
       
        // println!(
        //     "  R1CS:                     {:>12} bytes ({:>5.1}%)",
        //     r1cs_size,
        //     r1cs_size as f64 / total_size as f64 * 100.0
        // );

        // #[cfg(not(feature = "mavros_compiler"))]
        // {
        //     println!(
        //         "  SplitWitnessBuilders:     {:>12} bytes ({:>5.1}%)",
        //         split_witness_builders_size,
        //         split_witness_builders_size as f64 / total_size as f64 * 100.0
        //     );
        //     println!(
        //         "  NoirWitnessGenerator:     {:>12} bytes ({:>5.1}%)",
        //         witness_generator_size,
        //         witness_generator_size as f64 / total_size as f64 * 100.0
        //     );
        // }
        // println!(
        //     "  WhirR1CSScheme:           {:>12} bytes ({:>5.1}%)",
        //     whir_for_witness_size,
        //     whir_for_witness_size as f64 / total_size as f64 * 100.0
        // );
        // println!("  ------------------------------------------");
        // println!("  Total:                    {:>12} bytes", total_size);
        // println!();

        // let interner_size = postcard::to_allocvec(&prover.r1cs.interner)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // let matrix_a_size = postcard::to_allocvec(&prover.r1cs.a)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // let matrix_b_size = postcard::to_allocvec(&prover.r1cs.b)
        //     .map(|v| v.len())
        //     .unwrap_or(0);
        // let matrix_c_size = postcard::to_allocvec(&prover.r1cs.c)
        //     .map(|v| v.len())
        //     .unwrap_or(0);

        // println!("R1CS breakdown:");
        // println!(
        //     "  Interner:                 {:>12} bytes ({:>5.1}% of R1CS)",
        //     interner_size,
        //     interner_size as f64 / r1cs_size as f64 * 100.0
        // );
        // println!(
        //     "  Matrix A:                 {:>12} bytes ({:>5.1}% of R1CS)",
        //     matrix_a_size,
        //     matrix_a_size as f64 / r1cs_size as f64 * 100.0
        // );
        // println!(
        //     "  Matrix B:                 {:>12} bytes ({:>5.1}% of R1CS)",
        //     matrix_b_size,
        //     matrix_b_size as f64 / r1cs_size as f64 * 100.0
        // );
        // println!(
        //     "  Matrix C:                 {:>12} bytes ({:>5.1}% of R1CS)",
        //     matrix_c_size,
        //     matrix_c_size as f64 / r1cs_size as f64 * 100.0
        // );
        // println!();

        // let stats_a = prover.r1cs.a.delta_encoding_stats();
        // let stats_b = prover.r1cs.b.delta_encoding_stats();
        // let stats_c = prover.r1cs.c.delta_encoding_stats();

        // let total_absolute =
        //     stats_a.absolute_bytes + stats_b.absolute_bytes + stats_c.absolute_bytes;
        // let total_delta = stats_a.delta_bytes + stats_b.delta_bytes + stats_c.delta_bytes;
        // let total_savings = total_absolute.saturating_sub(total_delta);

        // println!("Delta encoding savings (column indices):");
        // println!(
        //     "  Matrix A:                 {:>12} bytes saved ({:>5.1}%)",
        //     stats_a.savings_bytes(),
        //     stats_a.savings_percent()
        // );
        // println!(
        //     "  Matrix B:                 {:>12} bytes saved ({:>5.1}%)",
        //     stats_b.savings_bytes(),
        //     stats_b.savings_percent()
        // );
        // println!(
        //     "  Matrix C:                 {:>12} bytes saved ({:>5.1}%)",
        //     stats_c.savings_bytes(),
        //     stats_c.savings_percent()
        // );
        // println!(
        //     "  Total:                    {:>12} bytes saved ({:>5.1}%)",
        //     total_savings,
        //     if total_absolute > 0 {
        //         total_savings as f64 / total_absolute as f64 * 100.0
        //     } else {
        //         0.0
        //     }
        // );
        // println!();

        // #[cfg(not(feature = "mavros_compiler"))]
        // {
        //     let w1_layers_size = postcard::to_allocvec(&prover.split_witness_builders.w1_layers)
        //         .map(|v| v.len())
        //         .unwrap_or(0);
        //     let w2_layers_size = postcard::to_allocvec(&prover.split_witness_builders.w2_layers)
        //         .map(|v| v.len())
        //         .unwrap_or(0);

        //     println!("SplitWitnessBuilders breakdown:");
        //     println!(
        //         "  W1 Layers:                {:>12} bytes ({:>5.1}% of SWB)",
        //         w1_layers_size,
        //         w1_layers_size as f64 / split_witness_builders_size as f64 * 100.0
        //     );
        //     println!(
        //         "  W2 Layers:                {:>12} bytes ({:>5.1}% of SWB)",
        //         w2_layers_size,
        //         w2_layers_size as f64 / split_witness_builders_size as f64 * 100.0
        //     );
        //     println!();
        // }
        // println!("Circuit statistics:");
        // println!(
        //     "  Constraints:              {:>12}",
        //     prover.r1cs.num_constraints()
        // );
        // println!(
        //     "  Witnesses:                {:>12}",
        //     prover.r1cs.num_witnesses()
        // );
        // println!(
        //     "  Public inputs:            {:>12}",
        //     prover.r1cs.num_public_inputs
        // );
        // println!();

        // let bytes_per_constraint = total_size as f64 / prover.r1cs.num_constraints() as f64;
        // println!(
        //     "Efficiency: {:.2} bytes/constraint (uncompressed)",
        //     bytes_per_constraint
        // );
        // println!();

        Ok(())
    }
}
