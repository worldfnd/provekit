use {
    super::{util::resolve_key_path, Command},
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

        let mut prover: Prover = read(&prover_path).context("while reading Provekit Prover")?;
        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        prover.set_produce_spark_query(self.produce_spark_query);

        let (proof, spark_queries) = prover
            .prove_with_toml(&input_path)
            .context("While proving Noir program statement")?;

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
