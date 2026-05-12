use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        Prover,
    },
    provekit_prover::Prove,
    std::path::PathBuf,
    tracing::{info, instrument},
};
#[cfg(test)]
use {provekit_common::Verifier, provekit_verifier::Verify};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

    #[cfg(test)]
    /// path to the verifier
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,

    /// path to store proof file
    #[argh(
        option,
        long = "out",
        short = 'o',
        default = "PathBuf::from(\"./proof.np\")"
    )]
    proof_path: PathBuf,

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
        // Read the scheme
        let mut prover: Prover =
            read(&self.prover_path).context("while reading Provekit Prover")?;
        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        prover.set_produce_spark_query(self.produce_spark_query);

        // Generate the proof
        let (proof, spark_queries) = prover
            .prove_with_toml(&self.input_path)
            .context("While proving Noir program statement")?;

        // Store the proof to file
        write(&proof, &self.proof_path).context("while writing proof")?;

        // Verify the proof (test-only; runs after write so we can move `proof`)
        #[cfg(test)]
        {
            let mut verifier: Verifier =
                read(&self.verifier_path).context("while reading Provekit Verifier")?;
            verifier
                .verify(&proof)
                .context("While verifying Noir proof")?;
        }

        if !spark_queries.is_empty() {
            std::fs::create_dir_all(&self.spark_queries_dir)
                .with_context(|| format!("creating {:?}", self.spark_queries_dir))?;
            for (index, query) in spark_queries.iter().enumerate() {
                let query_path = self
                    .spark_queries_dir
                    .join(format!("spark_query_{index}.json"));
                let query_file = std::fs::File::create(&query_path)
                    .with_context(|| format!("creating {query_path:?}"))?;
                serde_json::to_writer_pretty(query_file, query).context("writing spark query")?;
                info!("Wrote SPARK query to {query_path:?}");
            }
        }

        Ok(())
    }
}
