#![doc = include_str!("../README.md")]
mod compiler;
mod r1cs_emitter;
mod sparse_matrix;
mod utils;

use {
    self::{compiler::R1CS, sparse_matrix::SparseMatrix},
    acir::{AcirField, FieldElement},
    anyhow::{ensure, Context, Result as AnyResult},
    argh::FromArgs,
    noirc_artifacts::program::ProgramArtifact,
    rand::Rng,
    std::{fs::File, iter::zip, path::PathBuf, vec},
    tracing::{info, level_filters::LevelFilter},
    tracing_subscriber::{self, fmt::format::FmtSpan, EnvFilter},
    utils::PrintAbi,
};

/// Simple program to greet a person
#[derive(FromArgs)]
struct Args {
    #[argh(subcommand)]
    cmd: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Noir(NoirCmd),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "noir")]
/// Execute Noir VM
struct NoirCmd {
    /// path to the compiled Noir package file
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the witness file
    #[argh(positional)]
    witness_path: PathBuf,
}

fn main() -> AnyResult<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ACTIVE)
        .with_ansi(true)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .with_env_var("PROVEKIT_LOG")
                .from_env_lossy(),
        )
        .init();
    let args: Args = argh::from_env();
    match args.cmd {
        Command::Noir(cmd) => noir(cmd),
    }
}

fn noir(args: NoirCmd) -> AnyResult<()> {
    info!("Loading Noir program {:?}", args.program_path);
    let file = File::open(args.program_path).context("while opening Noir program")?;
    let program: ProgramArtifact =
        serde_json::from_reader(file).context("while reading Noir program")?;

    info!("Program noir version: {}", program.noir_version);
    info!("Program entry point: fn main{};", PrintAbi(&program.abi));
    ensure!(
        program.bytecode.functions.len() == 1,
        "Program must have one entry point."
    );
    let main = &program.bytecode.functions[0];
    info!(
        "ACIR: {} witnesses, {} opcodes.",
        main.current_witness_index,
        main.opcodes.len()
    );

    // Create the R1CS relation
    let mut r1cs = R1CS::new();
    r1cs.add_circuit(main);

    // Collect inputs and outputs
    let public_inputs = main
        .public_parameters
        .0
        .iter()
        .map(|w| r1cs.map_witness(*w))
        .collect::<Vec<_>>();
    let public_outputs = main
        .return_values
        .0
        .iter()
        .map(|w| r1cs.map_witness(*w))
        .collect::<Vec<_>>();
    let private_inputs = main
        .private_parameters
        .iter()
        .map(|w| r1cs.map_witness(*w))
        .collect::<Vec<_>>();

    info!(
        "R1CS: {} witnesses, {} constraints",
        r1cs.witnesses, r1cs.constraints
    );
    // dbg!(&r1cs);
    dbg!(&public_inputs);
    dbg!(&public_outputs);
    dbg!(&private_inputs);

    // Compute a satisfying witness
    let mut witness = vec![None; r1cs.witnesses];
    witness[0] = Some(FieldElement::one()); // Constant

    // Inputs
    witness[1] = Some(FieldElement::from(1234_u32)); // a
    witness[2] = Some(FieldElement::from(5678_u32)); // b

    // Solve constraints (this is how Noir expects it to be done, judging from ACVM)
    info!("Solving for witness.");
    for row in 0..r1cs.constraints {
        let [a, b, c] =
            [&r1cs.a, &r1cs.b, &r1cs.c].map(|mat| sparse_dot(mat.iter_row(row), &witness));
        let (val, mat) = match (a, b, c) {
            (Some(a), Some(b), Some(c)) => {
                assert_eq!(a * b, c, "Constraint {row} failed");
                continue;
            }
            (Some(a), Some(b), None) => (a * b, &r1cs.c),
            (Some(a), None, Some(c)) => (c / a, &r1cs.b),
            (None, Some(b), Some(c)) => (c / b, &r1cs.a),
            _ => panic!("Can not solve constraint {row}."),
        };
        let Some((col, val)) = solve_dot(mat.iter_row(row), &witness, val) else {
            panic!("Could not solve constraint {row}.")
        };
        // eprintln!("Constraint {row}: Solved for witness[{col}] = {val}");
        witness[col] = Some(val);
    }
    info!("Witness found.");

    // Complete witness with entropy.
    // TODO: Use better entropy source and proper sampling.
    let mut rng = rand::rng();
    let witness = witness
        .iter()
        .map(|f| f.unwrap_or_else(|| FieldElement::from(rng.random::<u128>())))
        .collect::<Vec<_>>();

    // dbg!(&witness);

    // Verify
    let a = mat_mul(&r1cs.a, &witness);
    let b = mat_mul(&r1cs.b, &witness);
    let c = mat_mul(&r1cs.c, &witness);
    a.iter()
        .zip(b.iter())
        .zip(c.iter())
        .enumerate()
        .for_each(|(row, ((&a, &b), &c))| {
            assert_eq!(a * b, c, "Constraint {row} failed");
        });
    info!("Witness verified.");

    // dbg!(&a);
    // dbg!(&b);
    // dbg!(&c);

    Ok(())
}

// Sparse dot product. `a` is assumed zero. `b` is assumed missing.
fn sparse_dot<'a>(
    a: impl Iterator<Item = (usize, &'a FieldElement)>,
    b: &[Option<FieldElement>],
) -> Option<FieldElement> {
    let mut accumulator = FieldElement::zero();
    for (col, &a) in a {
        accumulator += a * b[col]?;
    }
    Some(accumulator)
}

// Returns a pair (i, f) such that, setting `b[i] = f`,
// ensures `sparse_dot(a, b) = r`.
fn solve_dot<'a>(
    a: impl Iterator<Item = (usize, &'a FieldElement)>,
    b: &[Option<FieldElement>],
    r: FieldElement,
) -> Option<(usize, FieldElement)> {
    let mut accumulator = -r;
    let mut missing = None;
    for (col, &a) in a {
        if let Some(b) = b[col] {
            accumulator += a * b;
        } else if missing.is_none() {
            missing = Some((col, a));
        } else {
            return None;
        }
    }
    missing.map(|(col, coeff)| (col, -accumulator / coeff))
}

fn mat_mul(a: &SparseMatrix<FieldElement>, b: &[FieldElement]) -> Vec<FieldElement> {
    let mut result = vec![FieldElement::zero(); a.rows];
    for ((i, j), &value) in a.iter() {
        result[i] += value * b[j];
    }
    result
}
