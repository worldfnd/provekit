use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, spark::R1CSSparkQuery},
    provekit_spark::{SPARKProof, SPARKVerifier, SPARKVerifierScheme},
    std::{fs::File, io::BufReader, path::PathBuf},
    tracing::instrument,
};

/// Verify a standalone SPARK proof against a saved R1CSSparkQuery.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify-spark")]
pub struct Args {
    /// path to the SPARK proof file (.sp or .json)
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the R1CSSparkQuery JSON file
    #[argh(positional)]
    query_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        provekit_common::register_ntt();

        let (proof, query) = rayon::join(
            || read::<SPARKProof>(&self.proof_path).context("while reading SPARK proof"),
            || read_query(&self.query_path).context("while reading SPARK query"),
        );
        let proof = proof?;
        let query = query?;

        let scheme = SPARKVerifierScheme::from_proof(&proof);
        scheme
            .verify(proof, &query)
            .context("while verifying SPARK proof")?;

        Ok(())
    }
}

fn read_query(path: &PathBuf) -> Result<R1CSSparkQuery> {
    let file = File::open(path).with_context(|| format!("opening {path:?}"))?;
    serde_json::from_reader(BufReader::new(file)).context("parsing query JSON")
}
