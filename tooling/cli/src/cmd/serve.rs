use {
    super::{
        prepare::{self, SPARKCommitterScheme},
        Command,
    },
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        HashConfig, NoirProofScheme, Prover, TranscriptSponge, Verifier,
    },
    provekit_r1cs_compiler::NoirCompiler,
    provekit_spark::{
        SPARKProver, SPARKProverScheme, SerializableSparkWitnesses, SparkPreparedData,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        io::{Read, Write},
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

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,

    /// output directory for .pkp and .pkv files (default: current dir)
    #[argh(option, long = "output-dir", default = "PathBuf::from(\".\")")]
    output_dir: PathBuf,
}

#[derive(Deserialize)]
struct ProveRequest {
    circuit:    String,
    noir_proof: PathBuf,
    output:     PathBuf,
}

#[derive(Serialize)]
struct ProveResponse {
    ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_config = HashConfig::from_str(&self.hash).map_err(|e| anyhow::anyhow!("{}", e))?;

        provekit_common::register_ntt();

        let mut circuits: HashMap<String, SparkPreparedData> = HashMap::new();

        for spec in &self.circuit {
            let (name, path) = spec
                .split_once(':')
                .with_context(|| format!("invalid circuit spec '{spec}', expected name:path"))?;

            info!("Preparing circuit '{name}' from {path:?}");
            let (spark_data, scheme) = prepare_circuit(Path::new(path), hash_config)?;

            // Write .pkp and .pkv so provekit-prover can load them
            let pkp_path = self.output_dir.join(format!("{name}.pkp"));
            let pkv_path = self.output_dir.join(format!("{name}.pkv"));

            let prover = Prover::from_noir_proof_scheme(scheme.clone());
            let verifier = Verifier::from_noir_proof_scheme(scheme);
            write(&prover, &pkp_path).with_context(|| format!("writing prover for '{name}'"))?;
            write(&verifier, &pkv_path)
                .with_context(|| format!("writing verifier for '{name}'"))?;
            info!("Wrote {pkp_path:?} and {pkv_path:?}");

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
        println!("READY");

        for stream in listener.incoming() {
            let mut stream = stream.context("accepting connection")?;

            let request = read_request(&mut stream)?;
            let response = match handle_prove(&circuits, &request) {
                Ok(()) => ProveResponse {
                    ok:    true,
                    error: None,
                },
                Err(e) => ProveResponse {
                    ok:    false,
                    error: Some(format!("{e:?}")),
                },
            };
            write_response(&mut stream, &response)?;
        }

        Ok(())
    }
}

#[instrument(skip_all)]
fn prepare_circuit(
    program_path: &Path,
    hash_config: HashConfig,
) -> Result<(SparkPreparedData, NoirProofScheme)> {
    let scheme = NoirCompiler::from_file(program_path, hash_config)
        .context("while compiling Noir program")?;

    let whir_r1cs_scheme = match &scheme {
        NoirProofScheme::Noir(s) => s.whir_for_witness.clone(),
        NoirProofScheme::Mavros(s) => s.whir_for_witness.clone(),
    };

    let spark_r1cs = match &scheme {
        NoirProofScheme::Noir(noir) => prepare::build_spark_r1cs_noir(
            &noir.r1cs,
            whir_r1cs_scheme.m_0,
            whir_r1cs_scheme.m,
            whir_r1cs_scheme.w1_size,
            whir_r1cs_scheme.num_challenges,
        )?,
        NoirProofScheme::Mavros(_) => {
            anyhow::bail!("Mavros compiler not supported in serve mode")
        }
    };

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

    let spark_data = SparkPreparedData {
        matrix: spark_r1cs.into(),
        witnesses: SerializableSparkWitnesses::from(witnesses),
        commitments,
    };

    Ok((spark_data, scheme))
}

#[instrument(skip_all, fields(circuit = %request.circuit))]
fn handle_prove(
    circuits: &HashMap<String, SparkPreparedData>,
    request: &ProveRequest,
) -> Result<()> {
    let spark_data = circuits
        .get(&request.circuit)
        .with_context(|| format!("unknown circuit '{}'", request.circuit))?
        .clone();

    info!("Loading NoirProof from {:?}", request.noir_proof);
    let noir_proof: provekit_common::NoirProof =
        read(&request.noir_proof).context("reading NoirProof")?;
    let spark_query = noir_proof.r1cs_spark_query;

    let num_constraints = spark_data.matrix.num_rows;
    let num_witnesses = spark_data.matrix.num_cols;
    let num_nonzero = spark_data.matrix.val.len();

    info!("Proving ({num_constraints} constraints, {num_witnesses} witnesses)");
    let scheme = SPARKProverScheme::new(num_constraints, num_witnesses, num_nonzero);
    let proof = scheme
        .prove(spark_data, &spark_query)
        .context("generating SPARK proof")?;

    info!("Writing proof to {:?}", request.output);
    write(&proof, &request.output).context("writing spark proof")?;

    info!("Done");
    Ok(())
}

fn read_request(stream: &mut impl Read) -> Result<ProveRequest> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("reading request length")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .context("reading request body")?;

    serde_json::from_slice(&buf).context("parsing request JSON")
}

fn write_response(stream: &mut impl Write, response: &ProveResponse) -> Result<()> {
    let bytes = serde_json::to_vec(response).context("serializing response")?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .context("writing response length")?;
    stream.write_all(&bytes).context("writing response body")?;
    stream.flush().context("flushing response")?;
    Ok(())
}
