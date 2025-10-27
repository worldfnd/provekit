use {
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, utils::next_power_of_two, NoirProof, NoirProofScheme, Prover},
    provekit_spark::{SPARKProofGnark, SPARKProver, SPARKProverScheme},
    std::{fs::File, io::Write, path::PathBuf},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prove")]
#[argh(description = "Generate a SPARK proof")]
pub struct ProveArgs {
    /// path to NPS file
    #[argh(option)]
    noir_proof_scheme: PathBuf,

    /// path to NoirProof file (.np or .json) containing the SPARK statement
    #[argh(option)]
    noir_proof: PathBuf,

    /// output path for proof (default: spark_proof.json)
    #[argh(option, short = 'o', default = "PathBuf::from(\"spark_proof.json\")")]
    output: PathBuf,

    /// output path for gnark proof (default: gnark_spark_proof.json)
    #[argh(option, default = "PathBuf::from(\"gnark_spark_proof.json\")")]
    gnark_output: PathBuf,
}

pub fn execute(args: ProveArgs) -> Result<()> {
    println!("Loading R1CS from {:?}...", args.noir_proof_scheme);
    let scheme: Prover =
        read(&args.noir_proof_scheme).context("while reading Noir proof scheme")?;
    let mut r1cs = scheme.r1cs.clone().expect("while reading R1CS");
    r1cs.grow_matrices(
        1 << next_power_of_two(r1cs.num_constraints()),
        1 << next_power_of_two(r1cs.num_witnesses()),
    );
    drop(scheme);

    println!("Loading NoirProof from {:?}...", args.noir_proof);
    let noir_proof: NoirProof = read(&args.noir_proof).context("Failed to read NoirProof file")?;

    // Extract SPARK statement from the proof
    let spark_statement = noir_proof.spark_statement;
    println!("✓ Extracted SPARK statement from NoirProof");

    println!("Creating SPARK scheme...");
    let scheme = SPARKProverScheme::new_for_r1cs(&r1cs);

    println!("Generating SPARK proof...");
    let proof = scheme
        .prove(&r1cs, &spark_statement)
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

    println!("✓ SPARK proof generated successfully");
    Ok(())
}
