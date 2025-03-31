use {
    super::{utils::load_noir_program, Command},
    acir::{
        brillig::ForeignCallResult,
        circuit::{self, brillig::BrilligBytecode, Circuit},
        native_types::WitnessMap,
        FieldElement,
    },
    acvm::pwg::{ACVMStatus, ACVM},
    anyhow::{anyhow, Context, Result},
    argh::FromArgs,
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    noirc_abi::{
        input_parser::{Format, InputValue},
        Abi,
    },
    noirc_artifacts::program::ProgramArtifact,
    std::{
        collections::BTreeMap,
        fs::File,
        io::Read,
        path::{Path, PathBuf},
    },
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct ProveArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the prepared Noir program
    #[argh(positional)]
    prepared_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,
}

impl Command for ProveArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let program = load_noir_program(&self.program_path)?;
        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        let abi = program.abi;
        let input = read_input(&self.input_path, &abi)?;

        let brillig = program.bytecode.unconstrained_functions;
        let noir_witness = generate_noir_witness(&brillig, &main, input)?;

        Ok(())
    }
}

#[instrument(skip(abi), fields(size = input_path.metadata().map(|m| m.len()).ok()))]
fn read_input(input_path: &Path, abi: &Abi) -> Result<WitnessMap<FieldElement>> {
    let mut file = File::open(input_path).context("while opening input file")?;
    let mut input_string =
        String::with_capacity(file.metadata().map(|m| m.len() as usize).unwrap_or(0));
    file.read_to_string(&mut input_string)
        .context("while reading input file")?;
    let input = Format::Toml
        .parse(&input_string, abi)
        .context("while parsing input file")?;
    let map = abi
        .encode(&input, None)
        .context("while encoding input to witness map")?;
    Ok(map)
}

#[instrument(skip_all, fields(size = circuit.opcodes.len(), witnesses = circuit.current_witness_index))]
fn generate_noir_witness(
    brillig: &[BrilligBytecode<FieldElement>],
    circuit: &Circuit<FieldElement>,
    input: WitnessMap<FieldElement>,
) -> Result<WitnessMap<FieldElement>> {
    let solver = Bn254BlackBoxSolver::default();
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        input,
        brillig,
        &circuit.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::InProgress => Err(anyhow!("Execution halted unexpectedly")),
            ACVMStatus::RequiresForeignCall(info) => {
                let result = match info.function.as_str() {
                    "print" => {
                        eprintln!("NOIR PRINT: {:?}", info.inputs);
                        Ok(ForeignCallResult::default())
                    }
                    name => Err(anyhow!(
                        "Execution requires unimplemented foreign call to {name}"
                    )),
                }?;
                acvm.resolve_pending_foreign_call(result);
                Ok(())
            }
            ACVMStatus::RequiresAcirCall(_) => Err(anyhow!("Execution requires acir call")),
            ACVMStatus::Failure(error) => Err(error.into()),
        }
        .context("while running ACVM")?
    }
    Ok(acvm.finalize())
}
