use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::write, Prover, Verifier},
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    std::path::PathBuf,
    tracing::instrument,
};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct Args {
    /// path to the compiled Noir program (noir) or basic artifacts JSON
    /// (mavros)
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the R1CS file (required for mavros compiler)
    #[argh(option, long = "r1cs")]
    r1cs_path: Option<PathBuf>,

    /// compiler backend to use: "noir" (default) or "mavros"
    #[argh(option, long = "compiler", default = "String::from(\"noir\")")]
    compiler: String,

    /// output path for the prepared proof scheme
    #[argh(
        option,
        long = "pkp",
        short = 'p',
        default = "PathBuf::from(\"noir_proof_scheme.pkp\")"
    )]
    pkp_path: PathBuf,

    /// output path for the verifier
    #[argh(
        option,
        long = "pkv",
        short = 'v',
        default = "PathBuf::from(\"noir_proof_scheme.pkv\")"
    )]
    pkv_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let scheme = match self.compiler.as_str() {
            "noir" => NoirCompiler::from_file(&self.program_path)
                .context("while compiling Noir program")?,
            "mavros" => {
                let r1cs_path = self
                    .r1cs_path
                    .as_ref()
                    .context("--r1cs is required when using the mavros compiler")?;
                MavrosCompiler::compile(&self.program_path, r1cs_path)
                    .context("while compiling with Mavros")?
            }
            other => anyhow::bail!("Unknown compiler: {other}. Use \"noir\" or \"mavros\"."),
        };

        write(
            &Prover::from_noir_proof_scheme(scheme.clone()),
            &self.pkp_path,
        )
        .context("while writing Noir proof scheme")?;
        write(&Verifier::from_noir_proof_scheme(scheme), &self.pkv_path)
            .context("while writing Noir proof scheme")?;
        Ok(())
    }
}
