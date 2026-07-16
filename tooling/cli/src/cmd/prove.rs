#[cfg(test)]
use provekit_backend_bn254::{Verifier, Verify};
use {
    super::{util::resolve_key_path, Command},
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_backend_bn254::{Prove, Prover},
    provekit_common::file::{read, write},
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the ProveKit Prover (PKP) key (default: `<circuit>.pkp`)
    #[argh(option, long = "prover", short = 'p')]
    prover_path: Option<PathBuf>,

    /// path to the input values (default: ./Prover.toml)
    #[argh(option, long = "input", short = 'i')]
    input_path: Option<PathBuf>,

    /// path to store the proof file
    #[argh(
        option,
        long = "out",
        short = 'o',
        default = "PathBuf::from(\"./proof.np\")"
    )]
    proof_path: PathBuf,

    #[cfg(test)]
    /// path to the verifier key (default: `<circuit>.pkv`)
    #[argh(option, long = "verifier")]
    verifier_path: Option<PathBuf>,

    /// directory in which to write SPARK queries (default: ./spark_proofs)
    #[argh(
        option,
        long = "spark-queries-dir",
        default = "PathBuf::from(\"./spark_proofs\")"
    )]
    spark_queries_dir: PathBuf,

    /// produce SPARK queries and write them to `spark_queries_dir`.
    #[argh(switch, long = "produce-spark-query")]
    produce_spark_query: bool,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let prover_path = resolve_key_path(self.prover_path.as_deref(), "pkp")?;
        let input_path = self
            .input_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("./Prover.toml"));

        let prover: Prover = read(&prover_path).context("while reading Provekit Prover")?;
        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        let (proof, spark_queries) = if self.produce_spark_query {
            let (proof, batch) = prover
                .prove_with_spark_toml(&input_path)
                .context("While proving Noir program statement")?;
            (proof, Some(batch))
        } else {
            let proof = prover
                .prove_with_toml(&input_path)
                .context("While proving Noir program statement")?;
            (proof, None)
        };

        write(&proof, &self.proof_path).context("while writing proof")?;

        #[cfg(test)]
        {
            let verifier_path = resolve_key_path(self.verifier_path.as_deref(), "pkv")?;
            let mut verifier: Verifier =
                read(&verifier_path).context("while reading Provekit Verifier")?;
            verifier
                .verify(&proof)
                .context("While verifying Noir proof")?;
        }

        if let Some(batch) = &spark_queries {
            std::fs::create_dir_all(&self.spark_queries_dir)
                .with_context(|| format!("creating {:?}", self.spark_queries_dir))?;
            let queries_path = self.spark_queries_dir.join("spark_queries.json");
            let queries_file = std::fs::File::create(&queries_path)
                .with_context(|| format!("creating {queries_path:?}"))?;
            serde_json::to_writer_pretty(queries_file, batch).context("writing SPARK queries")?;
            info!(
                count = batch.queries.len(),
                "Wrote SPARK queries to {queries_path:?}"
            );
        }

        Ok(())
    }
}
