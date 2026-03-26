use {
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    serde::{Deserialize, Serialize},
    std::{
        io::{Read as _, Write as _},
        os::unix::net::UnixStream,
        path::PathBuf,
    },
    tracing::{info, instrument},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prove-remote")]
#[argh(description = "Request a SPARK proof from a running serve instance")]
pub struct ProveRemoteArgs {
    /// unix socket path of the running server
    #[argh(option)]
    socket: PathBuf,

    /// circuit name (must match a --circuit name on the server)
    #[argh(option)]
    circuit: String,

    /// path to NoirProof file (.np or .json)
    #[argh(option)]
    noir_proof: PathBuf,

    /// output path for SPARK proof (default: spark_proof.sp)
    #[argh(option, short = 'o', default = "PathBuf::from(\"spark_proof.sp\")")]
    output: PathBuf,
}

#[derive(Serialize)]
struct ProveRequest {
    circuit:    String,
    noir_proof: PathBuf,
    output:     PathBuf,
}

#[derive(Deserialize)]
struct ProveResponse {
    ok:    bool,
    error: Option<String>,
}

#[instrument(skip_all)]
pub fn execute(args: ProveRemoteArgs) -> Result<()> {
    info!("Connecting to server at {:?}", args.socket);
    let mut stream =
        UnixStream::connect(&args.socket).with_context(|| format!("connecting to {:?}", args.socket))?;

    let request = ProveRequest {
        circuit:    args.circuit,
        noir_proof: args.noir_proof,
        output:     args.output,
    };

    // Send request
    let bytes = serde_json::to_vec(&request).context("serializing request")?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .context("writing request length")?;
    stream.write_all(&bytes).context("writing request body")?;
    stream.flush().context("flushing request")?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("reading response length")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).context("reading response body")?;

    let response: ProveResponse = serde_json::from_slice(&buf).context("parsing response")?;

    if response.ok {
        info!("SPARK proof generated successfully");
        Ok(())
    } else {
        bail!(
            "server error: {}",
            response.error.unwrap_or_else(|| "unknown".to_string())
        )
    }
}
