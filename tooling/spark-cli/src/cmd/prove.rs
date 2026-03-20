use {
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Prover},
    provekit_spark::{SerializableSparkWitnesses, SparkCommitments, SparkWitnesses, types::SparkMatrix, SPARKProver, SPARKProverScheme},
    std::{fs::File, io::Write, path::PathBuf},
    tracing::{info, instrument},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prove")]
#[argh(description = "Generate a SPARK proof")]
pub struct ProveArgs {
    /// path to NPS file
    #[argh(option)]
    noir_proof_scheme: PathBuf,

    /// path to the spark R1CS matrix file
    #[argh(option, default = "PathBuf::from(\"spark_r1cs.bin\")")]
    spark_r1cs: PathBuf,

    /// path to NoirProof file (.np or .json) containing the SPARK statement
    #[argh(option)]
    noir_proof: PathBuf,

    /// path to the spark witnesses file
    #[argh(option, default = "PathBuf::from(\"spark_witnesses.bin\")")]
    spark_witnesses: PathBuf,

    /// path to the spark commitments file
    #[argh(option, default = "PathBuf::from(\"spark_commitments.bin\")")]
    spark_commitments: PathBuf,

    /// output path for proof (default: spark_proof.json)
    #[argh(option, short = 'o', default = "PathBuf::from(\"spark_proof.json\")")]
    output: PathBuf,
}

#[instrument(skip_all)]
pub fn execute(args: ProveArgs) -> Result<()> {
    provekit_common::register_ntt();

    info!("Loading prover scheme from {:?}", args.noir_proof_scheme);
    let _prover: Prover =
        read(&args.noir_proof_scheme).context("while reading Noir proof scheme")?;

    info!("Loading spark R1CS from {:?}", args.spark_r1cs);
    let spark_r1cs_bytes =
        std::fs::read(&args.spark_r1cs).context("while reading spark R1CS file")?;
    let spark_matrix: SparkMatrix =
        postcard::from_bytes(&spark_r1cs_bytes).context("while deserializing spark R1CS")?;

    info!("Loading spark witnesses from {:?}", args.spark_witnesses);
    let spark_witnesses_bytes =
        std::fs::read(&args.spark_witnesses).context("while reading spark witnesses file")?;
    let serializable_witnesses: SerializableSparkWitnesses =
        postcard::from_bytes(&spark_witnesses_bytes).context("while deserializing spark witnesses")?;
    let spark_witnesses: SparkWitnesses = serializable_witnesses.into();
    info!("Loaded spark witnesses");

    info!("Loading spark commitments from {:?}", args.spark_commitments);
    let commitments_bytes =
        std::fs::read(&args.spark_commitments).context("while reading spark commitments file")?;
    let commitments: SparkCommitments =
        postcard::from_bytes(&commitments_bytes).context("while deserializing spark commitments")?;
    info!("Loaded spark commitments");

    info!("Loading NoirProof from {:?}", args.noir_proof);
    let noir_proof: NoirProof = read(&args.noir_proof).context("Failed to read NoirProof file")?;

    let spark_query = noir_proof.r1cs_spark_query;
    info!("Extracted SPARK statement from NoirProof");

    let num_constraints = spark_matrix.timestamps.final_row.len();
    let num_witnesses = spark_matrix.timestamps.final_col.len();

    info!("Creating SPARK scheme ({num_constraints} constraints, {num_witnesses} witnesses)");
    let scheme = SPARKProverScheme::new(num_constraints, num_witnesses, spark_matrix.coo.val.len());

    info!("Generating SPARK proof...");
    let proof = scheme
        .prove(&spark_matrix, &spark_query, spark_witnesses, commitments)
        .context("Failed to generate proof")?;

    info!("Writing proof to {:?}", args.output);
    let mut file = File::create(&args.output).context("Failed to create output file")?;
    file.write_all(serde_json::to_string(&proof)?.as_bytes())
        .context("Failed to write proof")?;

    info!("SPARK proof generated successfully");
    Ok(())
}
