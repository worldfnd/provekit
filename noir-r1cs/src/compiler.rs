use {
    crate::SparseMatrix,
    acir::{
        circuit::{Circuit, Opcode},
        native_types::Expression,
        AcirField, FieldElement,
    },
    acvm::acir::circuit::Program,
    std::{collections::BTreeMap, default},
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, Default)]
pub struct R1CS {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,

    // Remapping of witness indices to the r1cs_witness array
    pub remap: BTreeMap<usize, usize>,
}

impl R1CS {
    pub fn add_circuit(&mut self, circuit: &Circuit<FieldElement>) {
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.add_constraint(expr),

                // TODO: Brillig is a VM used to generate witness values. It does not produce
                // constraints.
                Opcode::BrilligCall { .. } => unimplemented!("BrilligCall"),

                // Directive is a modern version of Brillig.
                Opcode::Directive(..) => unimplemented!("Directive"),

                // Calls to a function, this is to efficiently represent repeated structure in
                // circuits. TODO: We need to implement this so we can store
                // circuits concicely. It should not impact the R1CS constraints or
                // witness vector.
                Opcode::Call { .. } => unimplemented!("Call"),

                // These should be implemented using lookup arguments, or memory checking arguments.
                Opcode::MemoryOp { .. } => unimplemented!("MemoryOp"),
                Opcode::MemoryInit { .. } => unimplemented!("MemoryInit"),

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => unimplemented!("BlackBoxFuncCall"),
            }
        }
    }

    #[rustfmt::skip]
    pub fn add_constraint(&mut self, _expr: &Expression<FieldElement>) {
        // TODO: Ideally at this point all constraints are of the form A(w) * B(w) = C(w),
        // where A, B, and C are linear combinations of the witness vector w. We should
        // implement a compilation pass that ensures this is the case.

        todo!("Port over philipp's code below");
        /*
        // We only use one of the mul_terms per R1CS constraint in A and B
        // This isn't always the most efficient   way to do it though:
        // a * c + a * d + b * c + b * d    = (a + b) * (c + d) [1 instead of 4]
        // a * b + a * c    = a * (b + c) [1 instead of 2]
        // TODO: detect the    above cases and handle separately
        // TODO: ACIR    represents (a + b) * (c + d) as 3 EXPR opcodes, which are
        // translated with the below logic to 3 R1CS constraints, while it could    just
        // be a single one.
        if current_expr.mul_terms.len() > 1 {
            // Insert an additional constraint and temporary    witness at the end
            let (m, a, b) = current_expr.mul_terms[0];
            max_witness_index += 1; // Evaluate and create the temporary witness
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
        */
    }
}

pub fn compile(program: &Program<FieldElement>) {}

pub fn add_constraint(expr: &Expression<FieldElement>) {}
