use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::write, Prover, Verifier},
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    std::path::PathBuf,
    tracing::instrument,
};

#[derive(PartialEq, Eq, Debug)]
enum Compiler {
    Noir,
    Mavros,
}

impl argh::FromArgValue for Compiler {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "noir" => Ok(Compiler::Noir),
            "mavros" => Ok(Compiler::Mavros),
            other => Err(format!(
                "Unknown compiler: {other}. Use \"noir\" or \"mavros\"."
            )),
        }
    }
}

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
    #[argh(option, long = "compiler", default = "Compiler::Noir")]
    compiler: Compiler,

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

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let scheme = match self.compiler {
            Compiler::Noir => NoirCompiler::from_file(&self.program_path)
                .context("while compiling Noir program")?,
            Compiler::Mavros => {
                let r1cs_path = self
                    .r1cs_path
                    .as_ref()
                    .context("--r1cs is required when using the mavros compiler")?;
                MavrosCompiler::compile(&self.program_path, r1cs_path)
                    .context("while compiling with Mavros")?
            }
        };

        write(
            &Prover::from_noir_proof_scheme(scheme.clone()),
            &self.pkp_path,
        )
        .context("while writing Provekit Prover")?;
        write(&Verifier::from_noir_proof_scheme(scheme), &self.pkv_path)
            .context("while writing Provekit Verifier")?;
        Ok(())
    }
}
