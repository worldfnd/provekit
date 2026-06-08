use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, spark::SparkQueryBatch},
    provekit_spark::{SparkProof, SparkSetup, SparkVerifier, SparkVerifierScheme},
    std::{fs::File, io::BufReader, path::PathBuf},
    tracing::instrument,
};

/// Verify a standalone SPARK proof against the saved SparkQueryBatch.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify-spark")]
pub struct Args {
    /// path to the SPARK proof file (.sp or .json)
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the SPARK setup transcript (.spc) produced by `serve`
    #[argh(positional)]
    setup_path: PathBuf,

    /// path to the SPARK queries JSON file (`spark_queries.json`) written by `prove`
    #[argh(positional)]
    queries_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        provekit_common::register_ntt();

        let (proof, (setup, queries)) = rayon::join(
            || read::<SparkProof>(&self.proof_path).context("while reading SPARK proof"),
            || {
                rayon::join(
                    || read::<SparkSetup>(&self.setup_path).context("while reading SPARK setup"),
                    || {
                        read_queries(&self.queries_path)
                            .with_context(|| format!("while reading {:?}", self.queries_path))
                    },
                )
            },
        );
        let proof = proof?;
        let setup = setup?;
        let batch = queries?;

        anyhow::ensure!(
            !batch.queries.is_empty(),
            "SPARK queries file {:?} is empty",
            self.queries_path
        );

        SparkVerifierScheme
            .verify(proof, &setup, &batch)
            .context("while verifying SPARK proof")?;

        Ok(())
    }
}

fn read_queries(path: &PathBuf) -> Result<SparkQueryBatch> {
    let file = File::open(path).with_context(|| format!("opening {path:?}"))?;
    serde_json::from_reader(BufReader::new(file)).context("parsing SPARK queries JSON")
}
