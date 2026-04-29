use {
    super::{
        prepare::{self, Compiler, SPARKCommitterScheme},
        spark_protocol::{self, SparkRequest, SparkResponse},
        Command,
    },
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::write, HashConfig, NoirProofScheme, Prover, TranscriptSponge, Verifier,
    },
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    provekit_spark::{types::SparkMatrix, SPARKProver as _, SPARKProverScheme, SparkPreparedData},
    std::{
        collections::HashMap,
        os::unix::net::UnixListener,
        path::{Path, PathBuf},
        str::FromStr,
    },
    tracing::{info, instrument},
    whir::transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

/// Prepare circuits and serve SPARK proofs on a Unix socket
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "serve")]
pub struct Args {
    /// unix socket path to listen on
    #[argh(option)]
    socket: PathBuf,

    /// circuit to prepare, format: name:path/to/program.json (repeatable)
    #[argh(option)]
    circuit: Vec<String>,

    /// compiler backend: "noir" (default) or "mavros"
    #[argh(option, long = "compiler", default = "Compiler::Noir")]
    compiler: Compiler,

    /// path to R1CS file (required for mavros compiler)
    #[argh(option, long = "r1cs")]
    r1cs_path: Option<PathBuf>,

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,

    /// output directory for .pkp and .pkv files (default: current dir)
    #[argh(option, long = "output-dir", default = "PathBuf::from(\".\")")]
    output_dir: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_config = HashConfig::from_str(&self.hash).map_err(|e| anyhow::anyhow!("{}", e))?;

        provekit_common::register_ntt();

        std::fs::create_dir_all(&self.output_dir)
            .with_context(|| format!("creating output directory {:?}", self.output_dir))?;

        let mut circuits: HashMap<String, SparkPreparedData> = HashMap::new();

        for spec in &self.circuit {
            let (name, path) = spec
                .split_once(':')
                .with_context(|| format!("invalid circuit spec '{spec}', expected name:path"))?;

            info!("Preparing circuit '{name}' from {path:?}");
            let pkp_path = self.output_dir.join(format!("{name}.pkp"));
            let pkv_path = self.output_dir.join(format!("{name}.pkv"));
            let spc_path = self.output_dir.join(format!("{name}.spc"));

            let spark_data = prepare_circuit(
                Path::new(path),
                &self.compiler,
                self.r1cs_path.as_deref(),
                hash_config,
                &pkp_path,
                &pkv_path,
                &spc_path,
            )?;

            circuits.insert(name.to_string(), spark_data);
            info!("Circuit '{name}' ready");
        }

        // Clean up stale socket file
        let _ = std::fs::remove_file(&self.socket);

        let listener = UnixListener::bind(&self.socket)
            .with_context(|| format!("binding Unix socket at {:?}", self.socket))?;

        info!(
            "Server ready on {:?} with {} circuit(s)",
            self.socket,
            circuits.len()
        );

        let mut next_index: usize = 0;
        for stream in listener.incoming() {
            let mut stream = stream.context("accepting connection")?;

            let request: SparkRequest = spark_protocol::read_message(&mut stream)?;
            let response = match handle_prove(&circuits, &request, next_index) {
                Ok(()) => {
                    next_index += 1;
                    SparkResponse {
                        ok:    true,
                        error: None,
                    }
                }
                Err(e) => SparkResponse {
                    ok:    false,
                    error: Some(format!("{e:?}")),
                },
            };
            spark_protocol::write_message(&mut stream, &response)?;
        }

        Ok(())
    }
}

#[instrument(skip_all)]
fn prepare_circuit(
    program_path: &Path,
    compiler: &Compiler,
    r1cs_path: Option<&Path>,
    hash_config: HashConfig,
    pkp_path: &Path,
    pkv_path: &Path,
    spc_path: &Path,
) -> Result<SparkPreparedData> {
    let scheme = compile_scheme(program_path, compiler, r1cs_path, hash_config)?;
    let spark_r1cs = build_spark_matrix(&scheme, r1cs_path)?;
    let spark_data = commit_spark(spark_r1cs)?;
    write(&spark_data.commitments, spc_path)
        .with_context(|| format!("writing SPARK commitments to {spc_path:?}"))?;
    write_artifacts(scheme, pkp_path, pkv_path)?;
    Ok(spark_data)
}

#[instrument(skip_all)]
fn compile_scheme(
    program_path: &Path,
    compiler: &Compiler,
    r1cs_path: Option<&Path>,
    hash_config: HashConfig,
) -> Result<NoirProofScheme> {
    match compiler {
        Compiler::Noir => NoirCompiler::from_file(program_path, hash_config)
            .context("while compiling Noir program"),
        Compiler::Mavros => {
            let r1cs_path = r1cs_path.context("--r1cs is required for mavros compiler")?;
            MavrosCompiler::compile(program_path, r1cs_path, hash_config)
                .context("while compiling with Mavros")
        }
    }
}

#[instrument(skip_all)]
fn build_spark_matrix(scheme: &NoirProofScheme, r1cs_path: Option<&Path>) -> Result<SparkMatrix> {
    let whir_r1cs_scheme = match scheme {
        NoirProofScheme::Noir(s) => s.whir_for_witness.clone(),
        NoirProofScheme::Mavros(s) => s.whir_for_witness.clone(),
    };

    match scheme {
        NoirProofScheme::Noir(noir) => prepare::build_spark_r1cs_noir(
            &noir.r1cs,
            whir_r1cs_scheme.m_0,
            whir_r1cs_scheme.m,
            whir_r1cs_scheme.w1_size,
            whir_r1cs_scheme.num_challenges,
        ),
        NoirProofScheme::Mavros(_) => {
            let r1cs_path = r1cs_path.context("--r1cs is required for mavros compiler")?;
            prepare::build_spark_r1cs_mavros(
                r1cs_path,
                whir_r1cs_scheme.m_0,
                whir_r1cs_scheme.m,
                whir_r1cs_scheme.w1_size,
                whir_r1cs_scheme.num_challenges,
            )
        }
    }
}

#[instrument(skip_all)]
fn commit_spark(spark_r1cs: SparkMatrix) -> Result<SparkPreparedData> {
    let num_rows = spark_r1cs.timestamps.final_row.len();
    let num_cols = spark_r1cs.timestamps.final_col.len();
    let num_nz_vals = spark_r1cs.coo.val.len();

    let spark_committer_scheme = SPARKCommitterScheme::new(num_rows, num_cols, num_nz_vals);
    let ds = DomainSeparator::protocol(&spark_committer_scheme.whir_configs).instance(&Empty);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::default());
    let witnesses = spark_committer_scheme.commit(&mut merlin, &spark_r1cs);

    let proof = merlin.proof();
    let mut arthur = VerifierState::new(&ds, &proof, TranscriptSponge::default());
    let commitments =
        prepare::extract_commitments(&mut arthur, &spark_committer_scheme.whir_configs)?;

    Ok(SparkPreparedData {
        matrix: spark_r1cs,
        witnesses,
        commitments,
    })
}

#[instrument(skip_all)]
fn write_artifacts(scheme: NoirProofScheme, pkp_path: &Path, pkv_path: &Path) -> Result<()> {
    let prover = Prover::from_noir_proof_scheme(scheme.clone());
    let verifier = Verifier::from_noir_proof_scheme(scheme);
    write(&prover, pkp_path).context("while writing Provekit Prover")?;
    write(&verifier, pkv_path).context("while writing Provekit Verifier")?;
    info!("Wrote {pkp_path:?} and {pkv_path:?}");
    Ok(())
}

#[instrument(skip_all, fields(circuit = %request.circuit))]
fn handle_prove(
    circuits: &HashMap<String, SparkPreparedData>,
    request: &SparkRequest,
    index: usize,
) -> Result<()> {
    let spark_data = circuits
        .get(&request.circuit)
        .with_context(|| format!("unknown circuit '{}'", request.circuit))?;

    let num_constraints = spark_data.matrix.timestamps.final_row.len();
    let num_witnesses = spark_data.matrix.timestamps.final_col.len();
    let num_nonzero = spark_data.matrix.coo.val.len();

    info!("Proving ({num_constraints} constraints, {num_witnesses} witnesses)");
    let scheme = SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero);
    let proof = scheme
        .prove(spark_data, &request.spark_query)
        .context("generating SPARK proof")?;

    std::fs::create_dir_all("./spark_proofs").context("creating ./spark_proofs")?;
    let output_path = Path::new("./spark_proofs").join(format!("spark_proof_{index}.sp"));
    info!("Writing proof to {output_path:?}");
    write(&proof, &output_path).context("writing spark proof")?;

    let query_path = Path::new("./spark_proofs").join(format!("spark_query_{index}.json"));
    let query_file = std::fs::File::create(&query_path)
        .with_context(|| format!("creating {query_path:?}"))?;
    serde_json::to_writer_pretty(query_file, &request.spark_query)
        .context("writing spark query")?;
    info!("Wrote query to {query_path:?}");

    info!("Done");
    Ok(())
}
