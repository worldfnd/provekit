mod types;
mod utils;

use acir::{
    circuit::Opcode,
    native_types::{Expression, Witness, WitnessStack},
    AcirField, FieldElement,
};
use clap::{Parser, ValueEnum};
use std::{collections::HashMap, ops::Neg, vec};
use types::Program;
use utils::program_at_path;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    cmd: Command,

    /// Path to circuit file
    circuit_path: String,

    /// Path to witness file
    witness_path: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Command {
    R1CS,
    Groth16R1CS,
}

struct R1CSMatrix<F> {
    values: Vec<(usize, usize, F)>,
    n:      usize,
    m:      usize,
}

impl R1CSMatrix<FieldElement> {
    fn new() -> Self {
        Self {
            values: vec![],
            n:      0,
            m:      0,
        }
    }

    pub fn set(&mut self, i: usize, j: usize, value: FieldElement) {
        self.n = self.n.max(i + 1);
        self.m = self.m.max(j + 1);
        self.values.push((i, j, value));
    }

    pub fn resize(&mut self, n: usize, m: usize) {
        self.n = n;
        self.m = m;
    }

    /// Return the matrix as row-first
    pub fn get_matrix(&self) -> Vec<FieldElement> {
        let mut matrix = vec![FieldElement::zero(); self.n * self.m];
        for (i, j, value) in self.values.iter() {
            assert!(i < &self.n);
            assert!(j < &self.m);
            matrix[i * self.m + j] = *value;
        }
        matrix
    }
}

fn dot(a: &[FieldElement], b: &[FieldElement]) -> FieldElement {
    assert!(a.len() == b.len());
    let mut result = FieldElement::zero();
    for i in 0..a.len() {
        result += a[i] * b[i];
    }
    result
}

fn main() {
    let args = Args::parse();
    let program = program_at_path(args.circuit_path);

    assert!(
        program.functions.len() == 1,
        "only one function supported at the moment",
    );
    let Program {
        mut functions,
        unconstrained_functions: _,
    } = program;
    let circuit = functions.pop().unwrap();

    let witness_stack = std::fs::read(args.witness_path).unwrap();
    let mut witness_stack: WitnessStack<FieldElement> =
        WitnessStack::try_from(witness_stack.as_slice()).unwrap();

    assert!(witness_stack.length() == 1);
    let witness_map = witness_stack.pop().unwrap().witness;

    let mut r1cs_a = R1CSMatrix::new();
    let mut r1cs_b = R1CSMatrix::new();
    let mut r1cs_c = R1CSMatrix::new();
    let mut r1cs_w = vec![];
    let mut remap = HashMap::new();

    // 1 is always the first element in the witness
    r1cs_w.push(FieldElement::one());
    remap.insert(0, 0);

    for (idx, (w, v)) in witness_map.into_iter().enumerate() {
        r1cs_w.push(v);
        remap.insert(w.witness_index(), idx + 1);
    }

    println!("Private inputs: {:?}", circuit.private_parameters.len());
    println!("Public inputs:  {:?}", circuit.public_parameters.0.len());
    println!("Return values:  {:?}", circuit.return_values.0.len());

    let mut constraints = 0;
    let mut max_witness_index = circuit.current_witness_index;

    for opcode in circuit.opcodes.iter() {
        // println!("{:?}", opcode);
        match opcode {
            Opcode::AssertZero(expr) => {
                let mut current_expr: Expression<FieldElement> = (*expr).clone();
                loop {
                    // We only use one of the mul_terms per R1CS constraint in A and B
                    // This isn't always the most efficient way to do it though:
                    // a * c + a * d + b * c + b * d = (a + b) * (c + d) [1 instead of 4]
                    // a * b + a * c = a * (b + c) [1 instead of 2]
                    // TODO: detect the above cases and handle separately
                    // TODO: ACIR represents (a + b) * (c + d) as 3 EXPR opcodes, which are
                    // translated with the below logic to 3 R1CS constraints, while it could just be
                    // a single one.
                    if current_expr.mul_terms.len() > 1 {
                        // Insert an additional constraint and temporary witness at the end
                        let (m, a, b) = current_expr.mul_terms[0];
                        max_witness_index += 1;
                        // Evaluate and create the temporary witness
                        let w_val = m
                            * r1cs_w[*remap.get(&a.witness_index()).unwrap()]
                            * r1cs_w[*remap.get(&b.witness_index()).unwrap()];
                        remap.insert(max_witness_index, r1cs_w.len());
                        r1cs_w.push(w_val);

                        // Add constraint on temporary witness
                        r1cs_a.set(constraints, *remap.get(&a.witness_index()).unwrap(), m);
                        r1cs_b.set(
                            constraints,
                            *remap.get(&b.witness_index()).unwrap(),
                            FieldElement::one(),
                        );
                        r1cs_c.set(
                            constraints,
                            *remap.get(&max_witness_index).unwrap(),
                            FieldElement::one(),
                        );

                        // Remove the used mul_term
                        current_expr.mul_terms = current_expr.mul_terms[1..].to_vec();
                        // Add the temporary witness to the linear combinations (we'll constrain on
                        // all of them at once later)
                        current_expr
                            .linear_combinations
                            .push((FieldElement::one(), Witness::from(max_witness_index)));
                        constraints += 1;
                    } else {
                        // Either single mul_term left or none
                        if current_expr.mul_terms.len() == 1 {
                            let (m, a, b) = current_expr.mul_terms[0];
                            r1cs_a.set(constraints, *remap.get(&a.witness_index()).unwrap(), m);
                            r1cs_b.set(
                                constraints,
                                *remap.get(&b.witness_index()).unwrap(),
                                FieldElement::one(),
                            );
                        }

                        // Set all linear combinations and the constant in C
                        r1cs_c.set(constraints, 0, current_expr.q_c.neg());
                        for (m, c) in current_expr.linear_combinations {
                            r1cs_c.set(
                                constraints,
                                *remap.get(&c.witness_index()).unwrap(),
                                m.neg(),
                            );
                        }

                        constraints += 1;
                        break;
                    }
                }
            }
            Opcode::BlackBoxFuncCall(_) => unimplemented!("BlackBoxFuncCall"),
            Opcode::MemoryOp { .. } => unimplemented!("MemoryOp"),
            Opcode::MemoryInit { .. } => unimplemented!("MemoryInit"),
            Opcode::BrilligCall { .. } => unimplemented!("BrilligCall"),
            Opcode::Call { .. } => unimplemented!("Call"),
        }
    }

    match args.cmd {
        // If the R1CS is used for Groth16, add constraints on each of public inputs (and "outputs")
        // to protect against malleability (w_i * 0 = 0)
        Command::Groth16R1CS => {
            for public_input in circuit.public_parameters.0.into_iter() {
                r1cs_a.set(
                    constraints,
                    *remap.get(&public_input.witness_index()).unwrap(),
                    FieldElement::one(),
                );
                constraints += 1;
            }
            for public_outputs in circuit.return_values.0.into_iter() {
                r1cs_a.set(
                    constraints,
                    *remap.get(&public_outputs.witness_index()).unwrap(),
                    FieldElement::one(),
                );
                constraints += 1;
            }
        }
        _ => {}
    }

    // Resize all matrices to same size
    r1cs_a.resize(constraints, r1cs_w.len());
    r1cs_b.resize(constraints, r1cs_w.len());
    r1cs_c.resize(constraints, r1cs_w.len());

    println!("Opcodes:        {:?}", circuit.opcodes.len());
    println!("Witnesses:      {:?}", r1cs_w.len());
    println!("Constraints:    {:?}", constraints);

    let a = r1cs_a.get_matrix();
    let b = r1cs_b.get_matrix();
    let c = r1cs_c.get_matrix();

    // Verify r1cs contraints: Ax * Bx = Cx
    for i in 0..constraints {
        let ax = dot(&a[i * r1cs_w.len()..(i + 1) * r1cs_w.len()], &r1cs_w);
        let bx = dot(&b[i * r1cs_w.len()..(i + 1) * r1cs_w.len()], &r1cs_w);
        let cx = dot(&c[i * r1cs_w.len()..(i + 1) * r1cs_w.len()], &r1cs_w);
        assert!(ax * bx == cx, "Constraint {} is invalid.", i);

        println!(
            "({:?} x {:?}ᵀ) * ({:?} x {:?}ᵀ) = ({:?} x {:?}ᵀ)",
            &a[i * r1cs_w.len()..(i + 1) * r1cs_w.len()],
            &r1cs_w,
            &b[i * r1cs_w.len()..(i + 1) * r1cs_w.len()],
            &r1cs_w,
            &c[i * r1cs_w.len()..(i + 1) * r1cs_w.len()],
            &r1cs_w,
        );
    }

    println!("✅ All constraints are valid.")
}
