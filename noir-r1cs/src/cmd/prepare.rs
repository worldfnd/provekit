use {
    super::Command,
    crate::{compiler::R1CS, sparse_matrix::SparseMatrix, utils::PrintAbi},
    acir::{circuit::Circuit, FieldElement},
    anyhow::{ensure, Context as _, Result},
    argh::FromArgs,
    noirc_artifacts::program::ProgramArtifact,
    serde::Serialize,
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
        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );
        let r1cs = prepare_circuit(&main)?;
        info!(
            "R1CS: {} constraints, {} variables.",
            r1cs.constraints, r1cs.witnesses
        );
        write_r1cs_to_file(&r1cs, &self.output_path)?;
        Ok(())
    }
}

#[instrument(skip_all)]
fn load_noir_program(program_path: &Path) -> Result<ProgramArtifact> {
    let file = File::open(program_path).context("while opening Noir program")?;
    let program: ProgramArtifact =
        serde_json::from_reader(file).context("while reading Noir program")?;

    info!("Program noir version: {}", program.noir_version);
    info!("Program entry point: fn main{};", PrintAbi(&program.abi));
    ensure!(
        program.bytecode.functions.len() == 1,
        "Program must have one entry point."
    );

    Ok(program)
}

#[instrument(skip_all)]
fn prepare_circuit(circuit: &Circuit<FieldElement>) -> Result<R1CS> {
    // Create the R1CS relation
    let mut r1cs = R1CS::new();
    r1cs.add_circuit(circuit);
    Ok(r1cs)
}

#[instrument(skip_all)]
fn write_r1cs_to_file(r1cs: &R1CS, output_path: &Path) -> Result<()> {
    #[derive(Serialize)]
    struct JsonR1CS {
        num_public:      usize,
        num_variables:   usize,
        num_constraints: usize,
        a:               Vec<MatrixEntry>,
        b:               Vec<MatrixEntry>,
        c:               Vec<MatrixEntry>,
        witnesses:       Vec<Vec<FieldElement>>,
    }

    #[derive(Serialize)]
    struct MatrixEntry {
        constraint: usize,
        signal:     usize,
        value:      String,
    }

    fn matrix_to_entries(matrix: &SparseMatrix<FieldElement>) -> Vec<MatrixEntry> {
        matrix
            .iter()
            .map(|((constraint, signal), value)| MatrixEntry {
                constraint,
                signal,
                value: value.to_string(), // OPT: Stringify on the fly
            })
            .collect()
    }

    let json_r1cs = {
        let _span = span!(Level::INFO, "preparing R1CS struct").entered();
        JsonR1CS {
            num_public:      0, // TODO
            num_variables:   r1cs.witnesses,
            num_constraints: r1cs.constraints,
            a:               matrix_to_entries(&r1cs.a),
            b:               matrix_to_entries(&r1cs.b),
            c:               matrix_to_entries(&r1cs.c),
            witnesses:       Vec::new(), // TODO
        }
    };

    let _span = span!(Level::INFO, "writing R1CS to file").entered();
    let mut file = File::create(output_path).context("while creating output file")?;
    serde_json::to_writer_pretty(&mut file, &json_r1cs).context("while writing R1CS to file")?;
    Ok(())
}
