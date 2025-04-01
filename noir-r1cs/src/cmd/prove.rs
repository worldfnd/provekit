use {
    super::{utils::load_noir_program, Command},
    crate::{compiler::R1CS, witness::generate_witness},
    acir::{circuit::Circuit, native_types::WitnessMap, FieldElement},
    anyhow::{Context, Result},
    argh::FromArgs,
    noirc_abi::{input_parser::Format, Abi},
    std::{
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
        let abi = program.abi;
        let input = read_input(&self.input_path, &abi)?;
        let brillig = program.bytecode.unconstrained_functions;
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );
        let r1cs = prepare_circuit(&main)?;
        let witness = generate_witness(&r1cs, &brillig, &main, input)?;

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

#[instrument(skip_all, fields(opcodes = circuit.opcodes.len(), witnesses = circuit.current_witness_index))]
fn prepare_circuit(circuit: &Circuit<FieldElement>) -> Result<R1CS> {
    // Create the R1CS relation
    let mut r1cs = R1CS::new();
    r1cs.add_circuit(circuit);
    Ok(r1cs)
}
