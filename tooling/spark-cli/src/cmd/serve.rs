use {
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::file::{read, write},
    provekit_spark::{SPARKProver, SPARKProverScheme, SparkPreparedData},
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        io::{Read, Write},
        os::unix::net::UnixListener,
        path::{Path, PathBuf},
    },
    tracing::{info, instrument},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "serve")]
#[argh(description = "Start SPARK proving server on a Unix socket")]
pub struct ServeArgs {
    /// unix socket path to listen on
    #[argh(option)]
    socket: PathBuf,

    /// circuit to load, format: name:path/to/spark_data.spd (repeatable)
    #[argh(option)]
    circuit: Vec<String>,
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

#[instrument(skip_all)]
pub fn execute(args: ServeArgs) -> Result<()> {
    provekit_common::register_ntt();

    let mut circuits: HashMap<String, SparkPreparedData> = HashMap::new();
    for spec in &args.circuit {
        let (name, path) = spec
            .split_once(':')
            .with_context(|| format!("invalid circuit spec '{spec}', expected name:path"))?;

        info!("Loading spark data for '{name}' from {path:?}");
        let spark_data: SparkPreparedData =
            read(Path::new(path)).with_context(|| format!("reading spark data for '{name}'"))?;
        info!("Loaded spark data for '{name}'");

        circuits.insert(name.to_string(), spark_data);
    }

    // Clean up stale socket file
    let _ = std::fs::remove_file(&args.socket);

    let listener = UnixListener::bind(&args.socket)
        .with_context(|| format!("binding Unix socket at {:?}", args.socket))?;

    info!("SPARK server ready on {:?} with {} circuit(s)", args.socket, circuits.len());
    // Signal readiness — clients can wait for this line
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
    stream.read_exact(&mut len_buf).context("reading request length")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).context("reading request body")?;

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
