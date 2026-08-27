use {crate::Command, anyhow::Result, argh::FromArgs, std::path::PathBuf, tracing::instrument};

/// Generate input compatible with gnark.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-gnark-inputs")]
pub struct Args {
    /// path to the verifier data file
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the parameters file for gnark recursive verifier
    #[argh(
        option,
        long = "params",
        default = "String::from(\"./params_for_recursive_verifier\")"
    )]
    params_for_recursive_verifier: String,

    /// path to the r1cs output file
    #[argh(option, long = "r1cs", default = "String::from(\"./r1cs.json\")")]
    r1cs_path: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // The gnark exporter cannot describe zook's `ProtocolConfig`; the Go
        // recursive verifier needs a paired update first.
        anyhow::bail!(
            "cannot write gnark parameters to {}: gnark parameter export is not supported with \
             the zook witness commitment; the Go recursive verifier needs a paired update",
            self.params_for_recursive_verifier
        );
    }
}
