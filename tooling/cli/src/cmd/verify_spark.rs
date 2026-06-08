use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, spark::R1CSSparkQuery},
    provekit_spark::{SparkProof, SparkSetup, SparkVerifier, SparkVerifierScheme},
    std::{fs::File, io::BufReader, path::PathBuf},
    tracing::instrument,
};

/// Verify a standalone SPARK proof against the saved R1CSSparkQuery set.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify-spark")]
pub struct Args {
    /// path to the SPARK proof file (.sp or .json)
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the SPARK setup transcript (.spc) produced by `serve`
    #[argh(positional)]
    setup_path: PathBuf,

    /// paths to one or more R1CSSparkQuery JSON files (in transcript order)
    #[argh(positional, greedy)]
    query_paths: Vec<PathBuf>,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        provekit_common::register_ntt();

        anyhow::ensure!(
            !self.query_paths.is_empty(),
            "verify-spark needs at least one query path"
        );

        let (proof, (setup, queries)) = rayon::join(
            || read::<SparkProof>(&self.proof_path).context("while reading SPARK proof"),
            || {
                rayon::join(
                    || read::<SparkSetup>(&self.setup_path).context("while reading SPARK setup"),
                    || {
                        self.query_paths
                            .iter()
                            .map(|p| read_query(p).with_context(|| format!("while reading {p:?}")))
                            .collect::<Result<Vec<_>>>()
                    },
                )
            },
        );
        let proof = proof?;
        let setup = setup?;
        let queries = queries?;

        SparkVerifierScheme
            .verify(proof, &setup, &queries)
            .context("while verifying SPARK proof")?;

        Ok(())
    }
}

fn read_query(path: &PathBuf) -> Result<R1CSSparkQuery> {
    let file = File::open(path).with_context(|| format!("opening {path:?}"))?;
    serde_json::from_reader(BufReader::new(file)).context("parsing query JSON")
}
