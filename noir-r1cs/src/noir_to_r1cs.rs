use {
    crate::{
        r1cs_solver::{ConstantTerm, SumTerm, WitnessBuilder},
        utils::noir_to_native,
        FieldElement, NoirElement, R1CS,
    },
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness},
    },
    anyhow::{bail, Result},
    ark_std::One,
    std::{collections::BTreeMap, num::NonZeroU32, ops::Neg},
};

/// Compiles an ACIR circuit into an [R1CS] instance, comprising of the A, B,
/// and C R1CS matrices, along with the witness vector.
struct NoirToR1CSCompiler {
    r1cs: R1CS,

    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    // Maps indices of ACIR witnesses to indices of R1CS witnesses
    acir_to_r1cs_witness_map: BTreeMap<usize, usize>,
}

/// Compile a Noir circuit to a R1CS relation, returning the R1CS and a map from
/// Noir witness indices to R1CS witness indices.
pub fn noir_to_r1cs(
    circuit: &Circuit<NoirElement>,
) -> Result<(R1CS, Vec<Option<NonZeroU32>>, Vec<WitnessBuilder>)> {
    let mut compiler = NoirToR1CSCompiler::new();
    compiler.add_circuit(circuit)?;
    Ok(compiler.finalize())
}

impl NoirToR1CSCompiler {
    fn new() -> Self {
        let mut r1cs = R1CS::new();
        // Grow the matrices to account for the constant one witness.
        r1cs.add_witnesses(1);
        // We want to get the index of the witness_one index, which should be
        // the current number of witnesses minus one, meaning it is the only
        // witness that has been added so far.
        let witness_one_idx = r1cs.num_witnesses() - 1;
        dbg!(&r1cs.num_witnesses());
        assert_eq!(witness_one_idx, 0, "R1CS requires first witness to be 1");
        Self {
            r1cs,
            witness_builders: vec![WitnessBuilder::Constant(ConstantTerm(
                witness_one_idx,
                FieldElement::one(),
            ))],
            acir_to_r1cs_witness_map: BTreeMap::new(),
        }
    }

    /// Returns the R1CS and the witness map
    pub fn finalize(self) -> (R1CS, Vec<Option<NonZeroU32>>, Vec<WitnessBuilder>) {
        // Convert witness map to vector
        let len = self
            .acir_to_r1cs_witness_map
            .keys()
            .copied()
            .max()
            .map_or_else(|| 0, |i| i + 1);
        let mut map = vec![None; len];
        for (acir_witness_idx, r1cs_witness_idx) in self.acir_to_r1cs_witness_map {
            map[acir_witness_idx] =
                Some(NonZeroU32::new(r1cs_witness_idx as u32).expect("Index zero is reserved"));
        }
        (self.r1cs, map, self.witness_builders)
    }

    /// Index of the constant one witness
    pub const fn witness_one(&self) -> usize {
        0
    }

    /// The number of witnesses in the R1CS instance. This includes the constant
    /// one witness.
    pub fn num_witnesses(&self) -> usize {
        self.r1cs.num_witnesses()
    }

    // Add a new witness to the R1CS instance, returning its index. If the
    // witness builder implicitly maps an ACIR witness to an R1CS witness, then
    // record this.
    pub fn add_witness_builder(&mut self, witness_builder: WitnessBuilder) -> usize {
        let start_idx = self.num_witnesses();
        self.r1cs.add_witnesses(witness_builder.num_witnesses());
        // Add the witness to the mapping if it is an ACIR witness
        match &witness_builder {
            WitnessBuilder::Acir(r1cs_witness_idx, acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*acir_witness, *r1cs_witness_idx);
            }
            _ => {}
        }
        self.witness_builders.push(witness_builder);
        start_idx
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided,
    // creating a new R1CS witness (and builder) if required.
    pub fn fetch_r1cs_witness_index(&mut self, acir_witness_index: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness_index.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness_builder(WitnessBuilder::Acir(
                    self.num_witnesses(),
                    acir_witness_index.as_usize(),
                ))
            })
    }

    /// Add a new witness representing the product of two existing witnesses,
    /// and add an R1CS constraint enforcing this.
    pub(crate) fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness_builder(WitnessBuilder::Product(
            self.num_witnesses(),
            operand_a,
            operand_b,
        ));
        self.r1cs.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    /// Add a new witness representing the sum of existing witnesses, and add an
    /// R1CS constraint enforcing this. Vector consists of (optional
    /// coefficient, witness index) tuples, one for each summand. The
    /// coefficient is optional, and if it is None, the coefficient is 1.
    pub(crate) fn add_sum(&mut self, summands: Vec<SumTerm>) -> usize {
        let sum =
            self.add_witness_builder(WitnessBuilder::Sum(self.num_witnesses(), summands.clone()));
        let az = summands
            .iter()
            .map(|SumTerm(coeff, witness_idx)| (coeff.unwrap_or(FieldElement::one()), *witness_idx))
            .collect::<Vec<_>>();
        self.r1cs
            .add_constraint(&az, &[(FieldElement::one(), self.witness_one())], &[(
                FieldElement::one(),
                sum,
            )]);
        sum
    }

    /// Add an ACIR assert zero constraint.
    pub fn add_acir_assert_zero(&mut self, expr: &Expression<NoirElement>) {
        // Create individual constraints for all the multiplication terms and collect
        // their outputs
        let mut linear: Vec<(FieldElement, usize)> = vec![];
        let mut a: Vec<(FieldElement, usize)> = vec![];
        let mut b: Vec<(FieldElement, usize)> = vec![];

        if !expr.mul_terms.is_empty() {
            // Process all except the last multiplication term
            linear = expr
                .mul_terms
                .iter()
                .take(expr.mul_terms.len() - 1)
                .map(|(coeff, acir_witness_a, acir_witness_b)| {
                    let a = self.fetch_r1cs_witness_index(*acir_witness_a);
                    let b = self.fetch_r1cs_witness_index(*acir_witness_b);
                    (-noir_to_native(*coeff), self.add_product(a, b))
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let (final_coeff, final_acir_witness_a, final_acir_witness_b) =
                &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(
                noir_to_native(*final_coeff),
                self.fetch_r1cs_witness_index(*final_acir_witness_a),
            )];
            b = vec![(
                FieldElement::one(),
                self.fetch_r1cs_witness_index(*final_acir_witness_b),
            )];
        }

        // Extend with linear combinations
        linear.extend(expr.linear_combinations.iter().map(|term| {
            (
                noir_to_native(term.0).neg(),
                self.fetch_r1cs_witness_index(term.1),
            )
        }));

        // Add constant by multipliying with constant value one.
        linear.push((noir_to_native(expr.q_c).neg(), self.witness_one()));

        // Add a single linear constraint. We could avoid this by substituting
        // back into the last multiplication constraint.
        self.r1cs.add_constraint(&a, &b, &linear);
    }

    pub fn add_circuit(&mut self, circuit: &Circuit<NoirElement>) -> Result<()> {
        for opcode in &circuit.opcodes {
            match opcode {
                Opcode::AssertZero(expr) => self.add_acir_assert_zero(expr),

                // Brillig is only for witness generation and does not produce constraints.
                Opcode::BrilligCall { .. } => {}

                op => bail!("Unsupported Opcode {op}"),
            }
        }
        Ok(())
    }
}
