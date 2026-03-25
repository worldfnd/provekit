use {
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        NoirProof, Prover,
    },
    provekit_spark::{SPARKProver, SPARKProverScheme, SparkPreparedData},
    std::path::PathBuf,
    tracing::{info, instrument},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prove")]
#[argh(description = "Generate a SPARK proof")]
pub struct ProveArgs {
    /// path to NPS file
    #[argh(option)]
    noir_proof_scheme: PathBuf,

    /// path to NoirProof file (.np or .json) containing the SPARK statement
    #[argh(option)]
    noir_proof: PathBuf,

    /// path to the combined spark data file (matrix, witnesses, commitments)
    #[argh(option, default = "PathBuf::from(\"spark_data.spd\")")]
    spark_data: PathBuf,

    /// output path for proof (default: spark_proof.sp)
    #[argh(option, short = 'o', default = "PathBuf::from(\"spark_proof.sp\")")]
    output: PathBuf,
}

#[instrument(skip_all)]
pub fn execute(args: ProveArgs) -> Result<()> {
    provekit_common::register_ntt();

    info!("Loading prover scheme from {:?}", args.noir_proof_scheme);
    let _prover: Prover =
        read(&args.noir_proof_scheme).context("while reading Noir proof scheme")?;

    info!("Loading spark data from {:?}", args.spark_data);
    let spark_data: SparkPreparedData =
        read(&args.spark_data).context("while reading spark data")?;
    info!("Loaded spark data");

    info!("Loading NoirProof from {:?}", args.noir_proof);
    let noir_proof: NoirProof = read(&args.noir_proof).context("Failed to read NoirProof file")?;

    let spark_query = noir_proof.r1cs_spark_query;
    info!("Extracted SPARK statement from NoirProof");

    let num_constraints = spark_data.matrix.num_rows;
    let num_witnesses = spark_data.matrix.num_cols;
    let num_nonzero = spark_data.matrix.val.len();

    info!("Creating SPARK scheme ({num_constraints} constraints, {num_witnesses} witnesses)");
    let scheme = SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero);

    info!("Generating SPARK proof...");
    let proof = scheme
        .prove(spark_data, &spark_query)
        .context("Failed to generate proof")?;

    info!("Writing proof to {:?}", args.output);
    write(&proof, &args.output).context("while writing spark proof")?;

    info!("SPARK proof generated successfully");
    Ok(())
}
