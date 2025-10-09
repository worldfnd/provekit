use ::{
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_spark::{
        deserialize_r1cs, deserialize_request, SPARKProofGnark, SPARKProver, SPARKProverScheme,
    },
    std::{fs::File, io::Write, path::PathBuf},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prove")]
#[argh(description = "Generate a SPARK proof")]
pub struct ProveArgs {
    /// path to R1CS file
    #[argh(option)]
    r1cs: PathBuf,

    /// path to request file
    #[argh(option)]
    request: PathBuf,

    /// output path for proof (default: spark_proof.json)
    #[argh(option, short = 'o', default = "PathBuf::from(\"spark_proof.json\")")]
    output: PathBuf,

    /// output path for gnark proof (default: gnark_spark_proof.json)
    #[argh(option, default = "PathBuf::from(\"gnark_spark_proof.json\")")]
    gnark_output: PathBuf,
}

pub fn execute(args: ProveArgs) -> Result<()> {
    println!("Loading R1CS from {:?}...", args.r1cs);
    let r1cs = deserialize_r1cs(&args.r1cs).context("Failed to load R1CS")?;

    println!("Loading request from {:?}...", args.request);
    let request = deserialize_request(&args.request).context("Failed to load request")?;

    println!("Creating SPARK scheme...");
    let scheme = SPARKProverScheme::new_for_r1cs(&r1cs);

    println!("Generating proof...");
    let proof = scheme
        .prove(&r1cs, &request)
        .context("Failed to generate proof")?;

    // Write proof
    println!("Writing proof to {:?}...", args.output);
    let mut file = File::create(&args.output).context("Failed to create output file")?;
    file.write_all(serde_json::to_string(&proof)?.as_bytes())
        .context("Failed to write proof")?;

    // Write gnark proof
    println!("Writing gnark proof to {:?}...", args.gnark_output);
    let log_num_terms =
        provekit_common::utils::next_power_of_two(proof.matrix_dimensions.nonzero_terms);
    let gnark_proof = SPARKProofGnark::from_proof(&proof, log_num_terms);
    let mut gnark_file =
        File::create(&args.gnark_output).context("Failed to create gnark output file")?;
    gnark_file
        .write_all(serde_json::to_string(&gnark_proof)?.as_bytes())
        .context("Failed to write gnark proof")?;

    println!("✓ Proof generated successfully");
    Ok(())
}
