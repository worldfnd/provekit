use {
    super::{utils::load_noir_program, Command},
    acir::{circuit::Circuit, FieldElement},
    anyhow::{Context as _, Result},
    argh::FromArgs,
    noir_r1cs::{sparse_matrix::SparseMatrix, NoirProofScheme, R1CS},
    serde::{Serialize, Serializer},
    std::{
        fs::File,
        path::{Path, PathBuf},
    },
    tracing::{info, instrument, span, Level},
};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct PrepareArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// output path for the prepared R1CS file
    #[argh(option, default = "PathBuf::from(\"r1cs.json\")")]
    output_path: PathBuf,
}

impl Command for PrepareArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let program = load_noir_program(&self.program_path)?;

        let scheme = NoirProofScheme::from_program(&program)?;

        // TODO: Store to file.

        Ok(())
    }
}
