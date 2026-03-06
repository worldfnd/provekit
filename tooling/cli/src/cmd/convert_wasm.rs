use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, write},
        Prover, WasmProver,
    },
    std::path::PathBuf,
    tracing::instrument,
};

/// Convert a .pkp prover artifact to a lightweight .wpkp WASM prover artifact
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "convert-wasm")]
pub struct Args {
    /// path to the input .pkp prover artifact
    #[argh(positional)]
    pkp_path: PathBuf,

    /// output path for the .wpkp file (default: same name with .wpkp
    /// extension)
    #[argh(option, short = 'o')]
    output: Option<PathBuf>,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let prover: Prover = read(&self.pkp_path).context("while reading .pkp prover artifact")?;

        let wpkp_path = self
            .output
            .clone()
            .unwrap_or_else(|| self.pkp_path.with_extension("wpkp"));

        write(&WasmProver::from_prover(prover), &wpkp_path)
            .context("while writing .wpkp WASM prover artifact")?;

        Ok(())
    }
}
