use {
    super::{
        prepare::{build_spark_r1cs_mavros, build_spark_r1cs_noir},
        Command,
    },
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        spark::R1CSSparkQuery,
        utils::convert_mavros_r1cs_to_provekit,
        Prover, R1CS,
    },
    provekit_spark::{types::SparkMatrix, SPARKProver as _, SPARKProverScheme, SparkProverContext},
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

    /// path to the R1CS file (required for the mavros compiler)
    #[argh(option, long = "r1cs")]
    r1cs_path: Option<PathBuf>,
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

        // TODO: cache from `prepare --spark` instead of recomputing; blocked on
        // serde for `WhirWitness` over `ark_bn254::Fr`.
        let (spark_matrix, non_spark_r1cs) =
            build_spark_matrix(&prover, self.r1cs_path.as_deref())?;
        let hash_config = prover.whir_for_witness().hash_config;
        let (setup, witnesses) = provekit_spark::preprocess_spark(&spark_matrix, hash_config);
        let context = SparkProverContext {
            matrix: spark_matrix,
            non_spark_r1cs,
            witnesses,
            setup,
        };

        let num_constraints = context.matrix.timestamps.final_row.len();
        let num_witnesses = context.matrix.timestamps.final_col.len();
        let num_nonzero = context.matrix.coo.val.len();

        let scheme =
            SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero, hash_config);
        let spark_proof = scheme
            .prove(&context, &queries)
            .context("generating SPARK proof")?;
        let proof_path = self.spark_dir.join(format!("spark_proof.sp"));
        write(&spark_proof, &proof_path)
            .with_context(|| format!("writing SPARK proof to {proof_path:?}"))?;
        info!("Wrote SPARK proof to {proof_path:?}");

        // for (index, query) in queries.iter().enumerate() {
        //     let scheme =
        //         SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero,
        // hash_config);     let spark_proof = scheme
        //         .prove(&context, query)
        //         .context("generating SPARK proof")?;
        //     let proof_path = self.spark_dir.join(format!("spark_proof_{index}.sp"));
        //     write(&spark_proof, &proof_path)
        //         .with_context(|| format!("writing SPARK proof to {proof_path:?}"))?;
        //     info!("Wrote SPARK proof to {proof_path:?}");
        // }

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

fn build_spark_matrix(prover: &Prover, r1cs_path: Option<&Path>) -> Result<(SparkMatrix, R1CS)> {
    let whir = prover.whir_for_witness().clone();
    match prover {
        Prover::Noir(p) => {
            let matrix = build_spark_r1cs_noir(
                &p.r1cs,
                whir.m_0,
                whir.m,
                whir.w1_size,
                whir.num_challenges,
            )?;
            Ok((matrix, p.r1cs.clone()))
        }
        Prover::Mavros(_) => {
            let r1cs_path = r1cs_path
                .context("--r1cs is required for SPARK proving with the mavros compiler")?;
            let matrix = build_spark_r1cs_mavros(
                r1cs_path,
                whir.m_0,
                whir.m,
                whir.w1_size,
                whir.num_challenges,
            )?;
            let r1cs_bytes = std::fs::read(r1cs_path).context("while reading R1CS file")?;
            let mavros_r1cs: mavros_artifacts::R1CS = bincode::deserialize(&r1cs_bytes)
                .context("while deserializing R1CS from bincode")?;
            let r1cs = convert_mavros_r1cs_to_provekit(&mavros_r1cs);
            Ok((matrix, r1cs))
        }
    }
}
