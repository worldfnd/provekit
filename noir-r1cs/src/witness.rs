use {
    crate::{compiler::R1CS, sparse_matrix::SparseMatrix},
    acir::{
        brillig::ForeignCallResult,
        circuit::{brillig::BrilligBytecode, Circuit},
        native_types::{Witness, WitnessMap},
        AcirField as _, FieldElement,
    },
    acvm::pwg::{ACVMStatus, ACVM},
    anyhow::{anyhow, ensure, Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    rand::Rng as _,
    tracing::{info, instrument},
};

#[instrument(skip_all, fields(size = r1cs.witnesses))]
pub fn generate_witness(
    r1cs: &R1CS,
    brillig: &[BrilligBytecode<FieldElement>],
    circuit: &Circuit<FieldElement>,
    input: WitnessMap<FieldElement>,
) -> Result<Vec<FieldElement>> {
    let noir_witness = generate_noir_witness(&brillig, circuit, input)?;
    let mut witness = noir_to_r1cs_witness(noir_witness, &r1cs)?;
    solve_r1cs(&r1cs, witness.as_mut_slice())?;
    let witness = fill_witness(witness)?;
    verify_r1cs(&r1cs, &witness)?;
    Ok(witness)
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

#[instrument(skip_all, fields(size = r1cs.witnesses))]
fn noir_to_r1cs_witness(
    noir_witness: WitnessMap<FieldElement>,
    r1cs: &R1CS,
) -> Result<Vec<Option<FieldElement>>> {
    // Compute a satisfying witness
    let mut witness = vec![None; r1cs.witnesses];
    witness[0] = Some(FieldElement::one()); // Constant

    // Fill in R1CS witness values with the pre-computed ACIR witness values
    for (acir_witness_idx, witness_idx) in &r1cs.remap {
        witness[*witness_idx] = Some(noir_witness[&Witness(*acir_witness_idx as u32)]);
    }

    Ok(witness)
}

#[instrument(skip_all, fields(size = r1cs.witnesses))]
fn solve_r1cs(r1cs: &R1CS, witness: &mut [Option<FieldElement>]) -> Result<()> {
    // Solve constraints (this is how Noir expects it to be done, judging from ACVM)
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
            _ => {
                dbg!(a, b, c);
                panic!("Can not solve constraint {row}.")
            }
        };
        let Some((col, val)) = solve_dot(mat.iter_row(row), &witness, val) else {
            panic!("Could not solve constraint {row}.")
        };
        witness[col] = Some(val);
    }
    Ok(())
}

#[instrument(skip_all, fields(size = witness.len()))]
/// Complete witness with entropy.
fn fill_witness(witness: Vec<Option<FieldElement>>) -> Result<Vec<FieldElement>> {
    // TODO: Use better entropy source and proper sampling.
    let mut rng = rand::thread_rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                FieldElement::from(rng.gen::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}

#[instrument(skip_all, fields(size = witness.len(), constraints = r1cs.constraints))]
fn verify_r1cs(r1cs: &R1CS, witness: &[FieldElement]) -> Result<()> {
    // Verify
    let a = mat_mul(&r1cs.a, &witness);
    let b = mat_mul(&r1cs.b, &witness);
    let c = mat_mul(&r1cs.c, &witness);
    for (row, ((&a, &b), &c)) in a.iter().zip(b.iter()).zip(c.iter()).enumerate() {
        ensure!(a * b == c, "Constraint {row} failed");
    }
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
