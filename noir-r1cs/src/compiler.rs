use {
    crate::SparseMatrix,
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, WitnessMap},
        AcirField, FieldElement,
    },
    std::ops::Neg,
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, Default)]
pub struct R1CS {
    pub r1cs_a: SparseMatrix<FieldElement>,
    pub r1cs_b: SparseMatrix<FieldElement>,
    pub r1cs_c: SparseMatrix<FieldElement>,

    pub r1cs_w: Vec<FieldElement>,

    // the next row of constraints to be added
    current_constraint:    usize,
    // the next witness index to be added
    current_witness_index: usize,
    // the number of original variables
    original_witness:      usize,
    // pub r1cs_w: Vec<FieldElement>,
    // // Remapping of witness indices to the r1cs_witness array
    // pub remap: BTreeMap<usize, usize>,
}

impl R1CS {
    // assumption being
    // there are different types of expressions
    // - expression with only mul terms + linear combinations + qc are generally the
    //   ones that represent the intermediate products
    // - expression with mul terms + !!multiple!! linear combinations + qc +
    //   constant are the ones we need to manually add intermediate products to the
    //   r1cs_witness array
    pub fn new(circuit: &Circuit<FieldElement>, witness: WitnessMap<FieldElement>) -> Self {
        let mut r1cs = R1CS::default();
        let mut rows = 0;
        let mut additional_cols = 0;
        let mut max_witness_index = 0;

        // Find the maximum witness index by scanning through all opcodes
        for opcode in circuit.opcodes.iter() {
            if let Opcode::AssertZero(expr) = opcode {
                // fetch the max witness index, from mul_terms and linear_combinations
                for mul_term in expr.mul_terms.iter() {
                    let (_, a, b) = mul_term;
                    max_witness_index = max_witness_index.max(a.witness_index() as usize);
                    max_witness_index = max_witness_index.max(b.witness_index() as usize);
                }
                for (_, c) in expr.linear_combinations.iter() {
                    max_witness_index = max_witness_index.max(c.witness_index() as usize);
                }

                if expr.linear_combinations.iter().len() > 1 || expr.mul_terms.iter().len() > 1 {
                    // this expression does not automatically add intermediate products to the
                    // r1cs_witness array
                    for _term in expr.mul_terms.iter() {
                        additional_cols += 1; // 1 because of a*b from a, b
                        rows += 1;
                    }
                }
                rows += 1; // for the equality between all mul terms and
                           // linear combinations, and the constant term
            }
        }
        additional_cols += 1; // for the final 1 we insert right after the original_vars
        let cols = max_witness_index + 1 + additional_cols;

        // Initialize matrices with appropriate dimensions
        r1cs.r1cs_a = SparseMatrix::new(rows, cols, FieldElement::zero());
        r1cs.r1cs_b = SparseMatrix::new(rows, cols, FieldElement::zero());
        r1cs.r1cs_c = SparseMatrix::new(rows, cols, FieldElement::zero());

        r1cs.original_witness = max_witness_index;
        // we insert 1 to the end of r1cs_w,
        // and the next witness index, so max_witness_index + 2
        r1cs.current_witness_index = max_witness_index + 2;

        // initialize r1cs_w with the max_witness_index 0's
        r1cs.r1cs_w = vec![FieldElement::zero(); max_witness_index + 1];

        witness.into_iter().for_each(|(w, f)| {
            r1cs.r1cs_w[w.witness_index() as usize] = f;
        });
        r1cs.r1cs_w.push(FieldElement::one());
        
        assert_eq!(r1cs.r1cs_a.rows(), r1cs.r1cs_b.rows());
        assert_eq!(r1cs.r1cs_a.cols(), r1cs.r1cs_b.cols());
        assert_eq!(r1cs.r1cs_a.rows(), r1cs.r1cs_c.rows());
        assert_eq!(r1cs.r1cs_a.cols(), r1cs.r1cs_c.cols());


        println!("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx creating r1cs xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        println!("r1cs_w: {:?}", r1cs.r1cs_w);
        
        println!("r1cs rows: {:?}", r1cs.r1cs_a.rows());
        println!("r1cs cols: {:?}\n", r1cs.r1cs_a.cols());


        r1cs
    }

    pub fn add_circuit(&mut self, circuit: &Circuit<FieldElement>) {
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.add_constraint(expr),

                // TODO: Brillig is a VM used to generate witness values. It does not produce
                // constraints.
                Opcode::BrilligCall { .. } => {
                    println!("Opcode::BrilligCall");
                    unimplemented!("BrilligCall")
                }

                // Directive is a modern version of Brillig.
                Opcode::Directive(..) => {
                    println!("Opcode::Directive");
                    unimplemented!("Directive")
                }

                // Calls to a function, this is to efficiently represent repeated structure in
                // circuits. TODO: We need to implement this so we can store
                // circuits concicely. It should not impact the R1CS constraints or
                // witness vector.
                Opcode::Call { .. } => {
                    println!("Opcode::Call");
                    unimplemented!("Call")
                }

                // These should be implemented using lookup arguments, or memory checking arguments.
                Opcode::MemoryOp { .. } => {
                    println!("Opcode::MemoryOp");
                    unimplemented!("MemoryOp")
                }
                Opcode::MemoryInit { .. } => {
                    println!("Opcode::MemoryInit");
                    unimplemented!("MemoryInit")
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => {
                    println!("Opcode::BlackBoxFuncCall");
                    unimplemented!("BlackBoxFuncCall")
                }
            }
        }
    }

    #[rustfmt::skip]
    pub fn add_constraint(&mut self, current_expr: &Expression<FieldElement>) {
        println!("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx current_expr xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        println!("\t{:?}\n", current_expr);
        println!("constraints #{:?}", self.current_constraint);
        // TODO: Ideally at this point all constraints are of the form A(w) * B(w) = C(w),
        // where A, B, and C are linear combinations of the witness vector w. We should
        // implement a compilation pass that ensures this is the case.

        // todo!("Port over philipp's code below");
        /*
        // We only use one of the mul_terms per R1CS constraint in A and B
        // This isn't always the most efficient   way to do it though:
        // a * c + a * d + b * c + b * d    = (a + b) * (c + d) [1 instead of 4]
        // a * b + a * c    = a * (b + c) [1 instead of 2]
        // TODO: detect the    above cases and handle separately
        // TODO: ACIR    represents (a + b) * (c + d) as 3 EXPR opcodes, which are
        // translated with the below logic to 3 R1CS constraints, while it could    just
        // be a single one.
        */
        let mut constraints = self.current_constraint; // Start from current number of constraints

        // let mut current_witness_index = 0;
        // for mul_term in current_expr.mul_terms.iter() {
        //     let (_m, a, b) = mul_term;
        //     let a_idx = a.witness_index() as usize;
        //     let b_idx = b.witness_index() as usize;
        //     self.remap.insert(a_idx, current_witness_index);
        //     self.remap.insert(b_idx, current_witness_index + 1);
        //     current_witness_index += 2;
        // }
        // for (_m, c) in current_expr.linear_combinations.iter() {
        //     let c_idx = c.witness_index() as usize;
        //     self.remap.insert(c_idx, current_witness_index);
        //     current_witness_index += 1;
        // }
        // println!("current_witness_index11: {:?}", current_witness_index);

        let witness_index_before_this_expression = self.current_witness_index;
        if current_expr.linear_combinations.iter().len() > 1 || current_expr.mul_terms.iter().len() > 1 {
            println!("detected intermediate mul terms");
            for mul_term in current_expr.mul_terms.iter() {
                let (m, a, b) = mul_term;
                let a_idx = a.witness_index() as usize;
                let b_idx = b.witness_index() as usize;
                

                self.r1cs_a.set(constraints, a_idx, *m);
                self.r1cs_b.set(
                    constraints,
                    b_idx,
                    FieldElement::one(),
                );

                // assumptions:
                // the intermediate mul terms, a.k.a. ab of a*b,
                // are always added in the end of r1cs_w
                // and, we add 1 to the end of r1cs_w
                self.r1cs_c.set(
                    constraints,
                    self.current_witness_index,
                    FieldElement::one(),
                );
                // add the intermediate mul term to the end of r1cs_w
                self.current_witness_index += 1;
                constraints += 1;

                self.r1cs_w.push(
                    *m * self.r1cs_w[a_idx] * self.r1cs_w[b_idx]
                );
            }

            // in r1cs_a
            // set all intermediate mul terms to be 1
            // self.current_witness_index - 1 because the last term is 1
            for i in 0..(self.current_witness_index - witness_index_before_this_expression) {
                println!("adding intermediate mul term to r1cs_a");
                self.r1cs_a.set(constraints, witness_index_before_this_expression + i, FieldElement::one());
            }
            println!("done adding intermediate mul terms to r1cs_a");

            // should be only one more row of constraints left
            // a.k.a. conbine all the mul terms and linear combinations and the constant
            {
                // set all linear combinations to be 1
                for (m, a) in current_expr.linear_combinations.iter() {
                    let a_idx = a.witness_index() as usize;
                    self.r1cs_a.set(
                        constraints,
                        a_idx,
                        *m,
                    );
                }
                self.r1cs_b.set(constraints, self.original_witness + 1, FieldElement::one());
                // in r1cs_c
                // set the final_result term to be q_c, the constant term
                self.r1cs_c.set(constraints, self.original_witness + 1, current_expr.q_c.neg());
            }


        } else {
            println!("no intermediate mul terms");
            println!("assume only 1 mul and 1 linear combination");
            assert_eq!(current_expr.mul_terms.len(), 1);
            let mul_term = current_expr.mul_terms[0];
            let (m, a, b) = mul_term;
            let a_idx = a.witness_index() as usize;
            let b_idx = b.witness_index() as usize;

            self.r1cs_a.set(constraints, a_idx, m);
            self.r1cs_b.set(constraints, b_idx, FieldElement::one());

            assert_eq!(current_expr.linear_combinations.len(), 1);
            let linear_term = current_expr.linear_combinations[0];
            let (m, c) = linear_term;
            let c_idx = c.witness_index() as usize;
            self.r1cs_c.set(constraints, c_idx, m.neg());
            // in r1cs_c
            // set the final_result term to be q_c, the constant term
            self.r1cs_c.set(constraints, self.original_witness + 1, current_expr.q_c.neg());
        }


        constraints += 1;
        self.current_constraint = constraints;

        // print the r1cs_a, r1cs_b, r1cs_c
        println!("r1cs_a: {:?}", self.r1cs_a);
        println!("r1cs_b: {:?}", self.r1cs_b);
        println!("r1cs_c: {:?}", self.r1cs_c);
        println!("r1cs_w: {:?}", self.r1cs_w);
    }
}
