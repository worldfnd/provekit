use {
    super::{
        spark_protocol::{self, SparkRequest, SparkResponse},
        Command,
    },
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        Prover,
    },
    provekit_prover::Prove,
    std::{os::unix::net::UnixStream, path::PathBuf},
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
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let prover: Prover = read(&self.prover_path).context("while reading Provekit Prover")?;
        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Generate the proof
        let (proof, spark_queries) = prover
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

        // If a socket is provided, send each SPARK query to the server.
        if let Some(socket) = &self.socket {
            let circuit = self
                .circuit
                .as_ref()
                .context("--circuit is required when --socket is provided")?;

            info!("Connecting to SPARK server at {socket:?}");
            let mut stream =
                UnixStream::connect(socket).with_context(|| format!("connecting to {socket:?}"))?;

            for spark_query in spark_queries {
                let request = SparkRequest {
                    circuit: circuit.clone(),
                    spark_query,
                };

                spark_protocol::write_message(&mut stream, &request)?;
                let response: SparkResponse = spark_protocol::read_message(&mut stream)?;

                if response.ok {
                    info!("SPARK proof dispatched");
                } else {
                    bail!(
                        "SPARK server error: {}",
                        response.error.unwrap_or_else(|| "unknown".to_string())
                    );
                }
            }
        }

        Ok(())
    }
}
