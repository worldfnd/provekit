use ::{
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_spark::{deserialize_request, SPARKProof, SPARKVerifier, SPARKVerifierScheme},
    std::{fs, path::PathBuf},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
#[argh(description = "Verify a SPARK proof")]
pub struct VerifyArgs {
    /// path to proof file
    #[argh(option)]
    proof: PathBuf,

    /// path to request file
    #[argh(option)]
    request: PathBuf,
}

pub fn execute(args: VerifyArgs) -> Result<()> {
    println!("Loading proof from {:?}...", args.proof);
    let proof_str = fs::read_to_string(&args.proof).context("Failed to read proof file")?;
    let proof: SPARKProof =
        serde_json::from_str(&proof_str).context("Failed to deserialize proof")?;

    println!("Loading request from {:?}...", args.request);
    let request = deserialize_request(&args.request).context("Failed to load request")?;

    println!("Creating verification scheme...");
    let scheme = SPARKVerifierScheme::from_proof(&proof);

    println!("Verifying proof...");
    scheme
        .verify(&proof, &request)
        .context("Verification failed")?;

    println!("✓ Proof verified successfully");
    Ok(())
}
