use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        spark::SparkQueryBatch,
        Prover,
    },
    provekit_spark::{SparkProver as _, SparkProverScheme, SparkProverContext},
    std::{fs::File, io::BufReader, path::PathBuf},
    tracing::{info, instrument},
};

/// Generate SPARK proofs for the queries emitted by `prove`.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove-spark")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

    /// directory containing `spark_queries.json`; the SPARK proof is written
    /// here as `spark_proof.sp` (default: ./spark_proofs)
    #[argh(
        option,
        long = "spark-dir",
        default = "PathBuf::from(\"./spark_proofs\")"
    )]
    spark_dir: PathBuf,

    /// path to the SPARK prover context (matrix + witnesses + setup) written
    /// by `prepare --spark`
    #[argh(
        option,
        long = "spctx",
        default = "PathBuf::from(\"noir_proof_scheme.spctx\")"
    )]
    spctx_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        provekit_common::register_ntt();

        let prover: Prover = read(&self.prover_path).context("while reading Provekit Prover")?;

        let queries_path = self.spark_dir.join("spark_queries.json");
        if !queries_path.exists() {
            info!("No SPARK queries found at {queries_path:?}");
            return Ok(());
        }
        let batch = read_queries(&queries_path)?;

        let hash_config = prover.whir_for_witness().hash_config;
        let context: SparkProverContext = read(&self.spctx_path)
            .with_context(|| format!("reading SPARK prover context from {:?}", self.spctx_path))?;

        let num_constraints = context.matrix.timestamps.final_row.len();
        let num_witnesses = context.matrix.timestamps.final_col.len();
        let num_nonzero = context.matrix.coo.val.len();

        let scheme =
            SparkProverScheme::new(num_constraints, num_witnesses, num_nonzero, hash_config);
        let spark_proof = scheme
            .prove(&context, &batch)
            .context("generating SPARK proof")?;
        let proof_path = self.spark_dir.join("spark_proof.sp");
        write(&spark_proof, &proof_path)
            .with_context(|| format!("writing SPARK proof to {proof_path:?}"))?;
        info!("Wrote SPARK proof to {proof_path:?}");

        Ok(())
    }
}

fn read_queries(path: &PathBuf) -> Result<SparkQueryBatch> {
    let file = File::open(path).with_context(|| format!("opening {path:?}"))?;
    serde_json::from_reader(BufReader::new(file)).with_context(|| format!("parsing {path:?}"))
}
