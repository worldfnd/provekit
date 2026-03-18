use {
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof},
    provekit_spark::{SPARKProof, SPARKVerifier, SPARKVerifierScheme},
    std::{fs, path::PathBuf},
    tracing::info,
};

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
#[argh(description = "Verify a SPARK proof")]
pub struct VerifyArgs {
    /// path to proof file
    #[argh(option)]
    spark_proof: PathBuf,

    /// path to NoirProof file (.np or .json) containing the SPARK statement
    #[argh(option)]
    noir_proof: PathBuf,
}

pub fn execute(args: VerifyArgs) -> Result<()> {
    provekit_common::register_ntt();

    info!("Loading spark-proof from {:?}", args.spark_proof);
    let proof_str = fs::read_to_string(&args.spark_proof).context("Failed to read proof file")?;
    let proof: SPARKProof =
        serde_json::from_str(&proof_str).context("Failed to deserialize spark-proof")?;

    info!("Loading NoirProof from {:?}", args.noir_proof);
    let noir_proof: NoirProof = read(&args.noir_proof).context("Failed to read NoirProof file")?;

    let spark_statement = noir_proof.r1cs_spark_query;

    info!("Creating verification scheme...");
    let scheme = SPARKVerifierScheme::from_proof(&proof);

    info!("Verifying proof...");
    scheme
        .verify(proof, &spark_statement)
        .context("Verification failed")?;

    info!("Proof verified successfully");
    Ok(())
}
