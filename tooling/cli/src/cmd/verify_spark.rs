use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, spark::R1CSSparkQuery},
    provekit_spark::{SPARKProof, SPARKSetup, SPARKVerifier, SPARKVerifierScheme},
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

    /// path to the SPARK setup transcript (.spc) produced by `serve`
    #[argh(positional)]
    setup_path: PathBuf,

    /// path to the R1CSSparkQuery JSON file
    #[argh(positional)]
    query_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        provekit_common::register_ntt();

        let (proof, (setup, query)) = rayon::join(
            || read::<SPARKProof>(&self.proof_path).context("while reading SPARK proof"),
            || {
                rayon::join(
                    || read::<SPARKSetup>(&self.setup_path).context("while reading SPARK setup"),
                    || read_query(&self.query_path).context("while reading SPARK query"),
                )
            },
        );
        let proof = proof?;
        let setup = setup?;
        let query = query?;

        SPARKVerifierScheme
            .verify(proof, &setup, &query)
            .context("while verifying SPARK proof")?;

        Ok(())
    }
}

fn read_query(path: &PathBuf) -> Result<R1CSSparkQuery> {
    let file = File::open(path).with_context(|| format!("opening {path:?}"))?;
    serde_json::from_reader(BufReader::new(file)).context("parsing query JSON")
}
