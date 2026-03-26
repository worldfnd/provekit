use {
    super::Command,
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        Prover,
    },
    provekit_prover::Prove,
    serde::{Deserialize, Serialize},
    std::{
        io::{Read as _, Write as _},
        os::unix::net::UnixStream,
        path::PathBuf,
    },
    tracing::{info, instrument},
};
#[cfg(test)]
use {provekit_common::Verifier, provekit_verifier::Verify};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

    #[cfg(test)]
    /// path to the verifier
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,

    /// path to store proof file
    #[argh(
        option,
        long = "out",
        short = 'o',
        default = "PathBuf::from(\"./proof.np\")"
    )]
    proof_path: PathBuf,

    /// unix socket path of a running serve instance (enables SPARK proving)
    #[argh(option)]
    socket: Option<PathBuf>,

    /// circuit name on the server (required with --socket)
    #[argh(option)]
    circuit: Option<String>,

    /// output path for SPARK proof (default: spark_proof.sp)
    #[argh(
        option,
        long = "spark-out",
        default = "PathBuf::from(\"spark_proof.sp\")"
    )]
    spark_proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let prover: Prover = read(&self.prover_path).context("while reading Provekit Prover")?;
        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Generate the proof
        let proof = prover
            .prove_with_toml(&self.input_path)
            .context("While proving Noir program statement")?;

        // Store the proof to file
        write(&proof, &self.proof_path).context("while writing proof")?;

        // Verify the proof (test-only; runs after write so we can move `proof`)
        #[cfg(test)]
        {
            let mut verifier: Verifier =
                read(&self.verifier_path).context("while reading Provekit Verifier")?;
            verifier
                .verify(&proof)
                .context("While verifying Noir proof")?;
        }

        // If a socket is provided, send the proof to the SPARK server
        if let Some(socket) = &self.socket {
            let circuit = self
                .circuit
                .as_ref()
                .context("--circuit is required when --socket is provided")?;

            info!("Connecting to SPARK server at {socket:?}");
            let mut stream =
                UnixStream::connect(socket).with_context(|| format!("connecting to {socket:?}"))?;

            let request = SparkRequest {
                circuit:    circuit.clone(),
                noir_proof: self.proof_path.clone(),
                output:     self.spark_proof_path.clone(),
            };

            let bytes = serde_json::to_vec(&request).context("serializing request")?;
            stream
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .context("writing request length")?;
            stream.write_all(&bytes).context("writing request body")?;
            stream.flush().context("flushing request")?;

            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .context("reading response length")?;
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut buf = vec![0u8; len];
            stream
                .read_exact(&mut buf)
                .context("reading response body")?;

            let response: SparkResponse =
                serde_json::from_slice(&buf).context("parsing response")?;

            if response.ok {
                info!("SPARK proof written to {:?}", self.spark_proof_path);
            } else {
                bail!(
                    "SPARK server error: {}",
                    response.error.unwrap_or_else(|| "unknown".to_string())
                );
            }
        }

        Ok(())
    }
}

#[derive(Serialize)]
struct SparkRequest {
    circuit:    String,
    noir_proof: PathBuf,
    output:     PathBuf,
}

#[derive(Deserialize)]
struct SparkResponse {
    ok:    bool,
    error: Option<String>,
}
