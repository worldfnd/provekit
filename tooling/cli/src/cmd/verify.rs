use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Verifier},
    provekit_spark::{SPARKProof, SPARKVerifier, SPARKVerifierScheme},
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Verify a Noir proof
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the SPARK proof file (optional)
    #[argh(option, long = "spark-proof")]
    spark_proof_path: Option<PathBuf>,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Load verifier and proof in parallel (independent I/O + decompression)
        let (verifier, proof) = rayon::join(
            || read::<Verifier>(&self.verifier_path).context("while reading Provekit Verifier"),
            || read::<NoirProof>(&self.proof_path).context("while reading proof"),
        );
        let mut verifier = verifier?;
        let proof = proof?;

        // Verify the proof. Note that the WHIR verifier directly computes deferred
        // values internally, and doesn't return folding randomness or deferred
        // values. To correctly incorporate SPARK verifier, we need these values
        verifier
            .verify(&proof)
            .context("While verifying Noir proof")?;

        // Verify the SPARK proof if provided
        if let Some(spark_proof_path) = &self.spark_proof_path {
            info!("Verifying SPARK proof from {spark_proof_path:?}");
            let spark_proof: SPARKProof =
                read(spark_proof_path).context("while reading SPARK proof")?;
            let spark_statement = proof.r1cs_spark_query;
            let scheme = SPARKVerifierScheme::from_proof(&spark_proof);
            scheme
                .verify(spark_proof, &spark_statement)
                .context("While verifying SPARK proof")?;
            info!("SPARK proof verified successfully");
        }

        Ok(())
    }
}
