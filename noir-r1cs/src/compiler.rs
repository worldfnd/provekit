use {
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, WitnessMap},
        AcirField, FieldElement,
    },
    num_traits::Zero,
    sprs::{CsVecBase, TriMat},
    std::ops::Neg,
};

#[derive(Debug, Clone, PartialEq)]
pub struct FieldWrapper(FieldElement);

impl Zero for FieldWrapper {
    fn zero() -> Self {
        FieldWrapper(FieldElement::zero())
    }
    fn is_zero(&self) -> bool {
        self.0.eq(&FieldElement::zero())
    }
}

impl FieldWrapper {
    fn zero() -> Self {
        FieldWrapper(FieldElement::zero())
    }

    fn one() -> Self {
        FieldWrapper(FieldElement::one())
    }
}

// Add necessary operator implementations
impl std::ops::Mul for FieldWrapper {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FieldWrapper(self.0 * rhs.0)
    }
}

impl std::ops::Neg for FieldWrapper {
    type Output = Self;
    fn neg(self) -> Self {
        FieldWrapper(self.0.neg())
    }
}

impl From<FieldElement> for FieldWrapper {
    fn from(f: FieldElement) -> Self {
        FieldWrapper(f)
    }
}

impl std::ops::Add for FieldWrapper {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FieldWrapper(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for FieldWrapper {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl sprs::MulAcc for FieldWrapper {
    fn mul_acc(&mut self, lhs: &Self, rhs: &Self) {
        *self += lhs.clone() * rhs.clone();
    }
}

impl num_traits::One for FieldWrapper {
    fn one() -> Self {
        FieldWrapper::one()
    }
}

impl Default for FieldWrapper {
    fn default() -> Self {
        Self::zero()
    }
}

/// Represents a R1CS constraint system.
#[derive(Debug)]
pub struct R1CS {
    pub r1cs_a: TriMat<FieldWrapper>,
    pub r1cs_b: TriMat<FieldWrapper>,
    pub r1cs_c: TriMat<FieldWrapper>,

    pub r1cs_w: Vec<FieldWrapper>,

    // the next row of constraints to be added
    current_constraint:    usize,
    // the next witness index to be added
    current_witness_index: usize,
    // the number of original variables
    original_witness:      usize,
}

impl Default for R1CS {
    fn default() -> Self {
        Self {
            r1cs_a:                TriMat::new((0, 0)),
            r1cs_b:                TriMat::new((0, 0)),
            r1cs_c:                TriMat::new((0, 0)),
            r1cs_w:                Vec::new(),
            current_constraint:    0,
            current_witness_index: 0,
            original_witness:      0,
        }
    }
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

        let mut r1cs = R1CS {
            r1cs_a:                TriMat::new((rows, cols)),
            r1cs_b:                TriMat::new((rows, cols)),
            r1cs_c:                TriMat::new((rows, cols)),
            r1cs_w:                vec![FieldWrapper::zero(); max_witness_index + 1],
            current_constraint:    0,
            current_witness_index: max_witness_index + 2,
            original_witness:      max_witness_index,
        };

        witness.into_iter().for_each(|(w, f)| {
            r1cs.r1cs_w[w.witness_index() as usize] = FieldWrapper(f);
        });
        r1cs.r1cs_w.push(FieldWrapper::one());

        assert_eq!(r1cs.r1cs_a.rows(), r1cs.r1cs_b.rows());
        assert_eq!(r1cs.r1cs_a.cols(), r1cs.r1cs_b.cols());
        assert_eq!(r1cs.r1cs_a.rows(), r1cs.r1cs_c.rows());
        assert_eq!(r1cs.r1cs_a.cols(), r1cs.r1cs_c.cols());

        println!(
            "\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx creating r1cs xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );
        println!(
            "r1cs_w: {:?}",
            r1cs.r1cs_w.iter().map(|w| w.0).collect::<Vec<_>>()
        );

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
                    println!("Opcode::{:?}", opcode);
                    // unimplemented!("BrilligCall")
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

        // check that the (r1cs_a * r1cs_w) * (r1cs_b * r1cs_w) = r1cs_c * r1cs_w

        // Convert TriMat to CsMat for multiplication
        let csr_a = self.r1cs_a.to_csr::<usize>();
        let csr_b = self.r1cs_b.to_csr::<usize>();
        let csr_c = self.r1cs_c.to_csr::<usize>();

        // Convert witness vector to sparse format
        let w_sparse = CsVecBase::new(
            self.r1cs_w.len(),
            Vec::<usize>::from_iter(0..self.r1cs_w.len()),
            self.r1cs_w.clone(),
        );

        // Compute matrix-vector multiplications
        let a_w = &csr_a * &w_sparse;
        let b_w = &csr_b * &w_sparse;
        let c_w = &csr_c * &w_sparse;

        // Element-wise multiplication
        let mut ab_w = CsVecBase::empty(a_w.dim());
        for (i, a_val) in a_w.iter() {
            if let Some(b_val) = b_w.get(i) {
                ab_w.append(i, a_val.clone() * b_val.clone());
            }
        }

        // Check equality
        assert_eq!(ab_w, c_w, "R1CS check failed: (A*w)*(B*w) != C*w");
        println!("R1CS check passed: (A*w)*(B*w) = C*w");
        // println!("r1cs_a: {:?}", self.r1cs_a);
        // println!("r1cs_b: {:?}", self.r1cs_b);
        // println!("r1cs_c: {:?}", self.r1cs_c);
        // println!(
        //     "r1cs_w: {:?}",
        //     self.r1cs_w.iter().map(|w| w.0).collect::<Vec<_>>()
        // );
    }

    pub fn add_constraint(&mut self, current_expr: &Expression<FieldElement>) {
        println!(
            "\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx current_expr xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );
        println!("\t{:?}\n", current_expr);
        println!("constraints #{:?}", self.current_constraint);
        // TODO: Ideally at this point all constraints are of the form A(w) * B(w) =
        // C(w), where A, B, and C are linear combinations of the witness vector
        // w. We should implement a compilation pass that ensures this is the
        // case.

        // todo!("Port over philipp's code below");
        // We only use one of the mul_terms per R1CS constraint in A and B
        // This isn't always the most efficient   way to do it though:
        // a * c + a * d + b * c + b * d    = (a + b) * (c + d) [1 instead of 4]
        // a * b + a * c    = a * (b + c) [1 instead of 2]
        // TODO: detect the    above cases and handle separately
        // TODO: ACIR    represents (a + b) * (c + d) as 3 EXPR opcodes, which are
        // translated with the below logic to 3 R1CS constraints, while it could    just
        // be a single one.
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
        if current_expr.linear_combinations.iter().len() > 1
            || current_expr.mul_terms.iter().len() > 1
        {
            println!("detected intermediate mul terms");
            for mul_term in current_expr.mul_terms.iter() {
                let (m, a, b) = mul_term;
                let a_idx = a.witness_index() as usize;
                let b_idx = b.witness_index() as usize;

                // assumptions:
                // the intermediate mul terms, a.k.a. ab of a*b,
                // are always added in the end of r1cs_w
                self.r1cs_a
                    .add_triplet(constraints, a_idx, FieldWrapper(*m));
                self.r1cs_b
                    .add_triplet(constraints, b_idx, FieldWrapper::one());
                self.r1cs_c.add_triplet(
                    constraints,
                    self.current_witness_index,
                    FieldWrapper::one(),
                );
                // add the intermediate mul term to the end of r1cs_w
                self.current_witness_index += 1;
                constraints += 1;
                self.r1cs_w.push(FieldWrapper(
                    *m * self.r1cs_w[a_idx].0 * self.r1cs_w[b_idx].0,
                ));
            }

            // in r1cs_a
            // set all intermediate mul terms to be 1
            for i in 0..(self.current_witness_index - witness_index_before_this_expression) {
                println!("adding intermediate mul term to r1cs_a");
                self.r1cs_a.add_triplet(
                    constraints,
                    witness_index_before_this_expression + i,
                    FieldWrapper::one(),
                );
            }
            println!("done adding intermediate mul terms to r1cs_a");

            // should be only one more row of constraints left
            // a.k.a. conbine all the mul terms and linear combinations and the constant
            for (m, a) in current_expr.linear_combinations.iter() {
                let a_idx = a.witness_index() as usize;
                self.r1cs_a
                    .add_triplet(constraints, a_idx, FieldWrapper(*m));
            }

            // set the r1cs_b to be 1 for the final_result term
            self.r1cs_b
                .add_triplet(constraints, self.original_witness + 1, FieldWrapper::one());
            // set the final_result term to be q_c, the constant term
            self.r1cs_c.add_triplet(
                constraints,
                self.original_witness + 1,
                FieldWrapper(current_expr.q_c.neg()),
            );
        } else {
            println!("no intermediate mul terms");
            println!("assume only 1 mul and 1 linear combination");
            assert_eq!(current_expr.mul_terms.len(), 1);
            let (m, a, b) = current_expr.mul_terms[0];
            let a_idx = a.witness_index() as usize;
            let b_idx = b.witness_index() as usize;

            self.r1cs_a.add_triplet(constraints, a_idx, FieldWrapper(m));
            self.r1cs_b
                .add_triplet(constraints, b_idx, FieldWrapper::one());

            if current_expr.linear_combinations.len() == 1 {
                let (m, c) = current_expr.linear_combinations[0];
                let c_idx = c.witness_index() as usize;
                self.r1cs_c
                    .add_triplet(constraints, c_idx, FieldWrapper(m.neg()));
            }

            self.r1cs_c.add_triplet(
                constraints,
                self.original_witness + 1,
                FieldWrapper(current_expr.q_c.neg()),
            );
        }

        constraints += 1;
        self.current_constraint = constraints;
        // print the r1cs_a, r1cs_b, r1cs_c
        // println!("r1cs_a: {:?}", self.r1cs_a);
        // println!("r1cs_b: {:?}", self.r1cs_b);
        // println!("r1cs_c: {:?}", self.r1cs_c);
        // println!(
        //     "r1cs_w: {:?}",
        //     self.r1cs_w.iter().map(|w| w.0).collect::<Vec<_>>()
        // );
    }
}
