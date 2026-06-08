use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        spark::R1CSSparkQuery,
        Prover,
    },
    provekit_spark::{SPARKProver as _, SPARKProverScheme, SparkProverContext},
    std::{
        fs::File,
        io::BufReader,
        path::{Path, PathBuf},
    },
    tracing::{info, instrument},
};

/// Generate SPARK proofs for the queries emitted by `prove`.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove-spark")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

    /// directory containing `spark_query_<i>.json` files; SPARK proofs are
    /// written here as `spark_proof_<i>.sp` (default: ./spark_proofs)
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

        let queries = collect_queries(&self.spark_dir)?;
        if queries.is_empty() {
            info!("No SPARK queries found in {:?}", self.spark_dir);
            return Ok(());
        }

        let hash_config = prover.whir_for_witness().hash_config;
        let context: SparkProverContext = read(&self.spctx_path)
            .with_context(|| format!("reading SPARK prover context from {:?}", self.spctx_path))?;

        let num_constraints = context.matrix.timestamps.final_row.len();
        let num_witnesses = context.matrix.timestamps.final_col.len();
        let num_nonzero = context.matrix.coo.val.len();

        let scheme =
            SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero, hash_config);
        let spark_proof = scheme
            .prove(&context, &queries)
            .context("generating SPARK proof")?;
        let proof_path = self.spark_dir.join("spark_proof.sp");
        write(&spark_proof, &proof_path)
            .with_context(|| format!("writing SPARK proof to {proof_path:?}"))?;
        info!("Wrote SPARK proof to {proof_path:?}");

        Ok(())
    }
}

fn collect_queries(dir: &Path) -> Result<Vec<R1CSSparkQuery>> {
    let mut out = Vec::new();
    for index in 0usize.. {
        let path = dir.join(format!("spark_query_{index}.json"));
        if !path.exists() {
            break;
        }
        let file = File::open(&path).with_context(|| format!("opening {path:?}"))?;
        let query: R1CSSparkQuery = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("parsing {path:?}"))?;
        out.push(query);
    }
    Ok(out)
}
