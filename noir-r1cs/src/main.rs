#![doc = include_str!("../README.md")]
mod compiler;
mod sparse_matrix;
mod utils;

use {
    self::{compiler::R1CS, sparse_matrix::SparseMatrix}, acir::{native_types::Witness as AcirWitness, AcirField, FieldElement}, anyhow::{ensure, Context, Result as AnyResult}, argh::FromArgs, compiler::WitnessBuilder, noirc_artifacts::program::ProgramArtifact, rand::Rng, std::{fs::File, path::PathBuf, vec}, tracing::{field::Field, info, level_filters::LevelFilter}, tracing_subscriber::{self, fmt::format::FmtSpan, EnvFilter}, utils::{file_io::deserialize_witness_stack, PrintAbi}
};

/// Prove & verify a compiled Noir program using R1CS.
#[derive(FromArgs)]
struct Args {
    /// path to the compiled Noir program
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
    prove_verify(args)
}

fn prove_verify(args: Args) -> AnyResult<()> {
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
    let num_public_parameters = main.public_parameters.0.len();
    let num_acir_witnesses = main.current_witness_index as usize;
    info!(
        "ACIR: {} witnesses, {} opcodes.",
        num_acir_witnesses,
        main.opcodes.len()
    );

    let mut witness_stack: acir::native_types::WitnessStack<FieldElement> =
        deserialize_witness_stack(args.witness_path.to_str().unwrap())?;

    let witness_stack = witness_stack.pop().unwrap().witness;

    if num_acir_witnesses < 15 {
        println!("ACIR witness values:");
        (0..num_acir_witnesses).for_each(|i| {
            println!("{}: {:?}", i, witness_stack[&AcirWitness(i as u32)]);
        });
    }

    // Create the R1CS relation
    let r1cs = R1CS::from_acir(main);
    print!("{}", r1cs);

    // Compute a satisfying witness
    // FIXME where does this block of code belong?  witness_builders should be a private field of R1CS.
    let mut rng = rand::thread_rng();
    let mut witness: Vec<Option<FieldElement>> = vec![None; r1cs.num_witnesses()];
    r1cs.witness_builders.iter().enumerate().for_each(|(witness_idx, witness_builder)| {
        assert_eq!(witness[witness_idx], None, "Witness {witness_idx} already set.");
        let value = match witness_builder {
            WitnessBuilder::Constant(c) => *c,
            WitnessBuilder::Acir(acir_witness_idx) => {
                witness_stack[&AcirWitness(*acir_witness_idx as u32)]
            },
            WitnessBuilder::MemoryRead(acir_witness_idx) => {
                witness_stack[&AcirWitness(*acir_witness_idx as u32)]
            },
            WitnessBuilder::Challenge => {
                // FIXME use a transcript to generate the challenge!
                FieldElement::from(rng.gen::<u128>())
            },
            WitnessBuilder::Inverse(operand_idx) => {
                let operand: FieldElement = witness[*operand_idx].unwrap();
                operand.inverse()
            },
            WitnessBuilder::Product(operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a].unwrap();
                let b: FieldElement = witness[*operand_idx_b].unwrap();
                a * b
            },
            WitnessBuilder::Sum(operands) => {
                unimplemented!("TODO tomorrow!");
                //operands.iter().map(|idx| witness[*idx].unwrap()).sum()
            },
            WitnessBuilder::MemoryAccessCount(block_id, addr) => {
                unimplemented!("TODO tomorrow!");
            },
            WitnessBuilder::Solvable(constraint_idx) => {
                // FIXME: copied from earlier code, but could be more general?  e.g. when both a and c contain reference the same (as yet unknown) witness index.
                let [a, b, c] =
                    [&r1cs.a, &r1cs.b, &r1cs.c].map(|mat| sparse_dot(mat.iter_row(*constraint_idx), &witness));
                let (val, mat) = match (a, b, c) {
                    (Some(_), Some(_), Some(_)) => {
                        panic!("Constraint {constraint_idx} contains no unknowns.")
                    }
                    (Some(a), Some(b), None) => (a * b, &r1cs.c),
                    (Some(a), None, Some(c)) => (c / a, &r1cs.b),
                    (None, Some(b), Some(c)) => (c / b, &r1cs.a),
                    _ => {
                        dbg!(a, b, c);
                        panic!("Can not solve constraint {constraint_idx}.")
                    },
                };
                let Some((solved_witness_idx, value)) = solve_dot(mat.iter_row(*constraint_idx), &witness, val) else {
                    panic!("Could not solve constraint {constraint_idx}.")
                };
                assert_eq!(solved_witness_idx, witness_idx, "Constraint {constraint_idx} solved the wrong witness.");
                value
            }
        };
        // TODO add to Transcript
        witness[witness_idx] = Some(value);
    });

    // Complete witness with entropy.
    // TODO: Use better entropy source and proper sampling.
    // FIXME is this the correct behaviour?  Would an error be more appropriate?
    let mut rng = rand::thread_rng();
    let witness = witness
        .iter()
        .map(|f| f.unwrap_or_else(|| FieldElement::from(rng.gen::<u128>())))
        .collect::<Vec<_>>();

    dbg!(&witness);

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

    r1cs.write_json_to_file(num_public_parameters, &witness, "r1cs.json")?;

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
