use {
    crate::{utils::noir_to_native, FieldElement, NoirElement, R1CS},
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness},
    },
    anyhow::{bail, Result},
    ark_std::One,
    std::{collections::BTreeMap, ops::Neg},
};

struct NoirToR1CSCompiler {
    r1cs:        R1CS,
    witness_one: usize,
    witness_map: BTreeMap<usize, usize>,
}

/// Compile a Noir circuit to a R1CS relation, returning the R1CS and a map from
/// Noir witness indices to R1CS witness indices.
pub fn noir_to_r1cs(circuit: &Circuit<NoirElement>) -> Result<(R1CS, BTreeMap<usize, usize>)> {
    let mut compiler = NoirToR1CSCompiler::new();
    compiler.add_circuit(circuit)?;
    Ok(compiler.finalize())
}

impl NoirToR1CSCompiler {
    fn new() -> Self {
        let mut r1cs = R1CS::new();
        let witness_one = r1cs.new_witness();
        assert_eq!(witness_one, 0, "R1CS requires first witness to be 1");
        Self {
            r1cs,
            witness_one,
            witness_map: BTreeMap::new(),
        }
    }

    /// Returns the R1CS and the witness map
    pub fn finalize(self) -> (R1CS, BTreeMap<usize, usize>) {
        (self.r1cs, self.witness_map)
    }

    /// Index of the constant one witness
    pub fn witness_one(&self) -> usize {
        self.witness_one
    }

    /// Map ACIR Witnesses to r1cs_witness indices
    pub fn map_witness(&mut self, witness: Witness) -> usize {
        self.witness_map
            .get(&witness.as_usize())
            .copied()
            .unwrap_or_else(|| {
                let value = self.r1cs.new_witness();
                self.witness_map.insert(witness.as_usize(), value);
                value
            })
    }

    /// Add an ACIR assert zero constraint.
    pub fn add_assert_zero(&mut self, expr: &Expression<NoirElement>) {
        // println!("expr {:?}", expr);
        // Create individual constraints for all the multiplication terms and collect
        // their outputs
        let mut linear: Vec<(FieldElement, usize)> = vec![];
        let mut a: Vec<(FieldElement, usize)> = vec![];
        let mut b: Vec<(FieldElement, usize)> = vec![];

        if expr.mul_terms.len() >= 1 {
            // Process all except the last multiplication term
            linear = expr
                .mul_terms
                .iter()
                .take(expr.mul_terms.len() - 1)
                .map(|term| {
                    let a = self.map_witness(term.1);
                    let b = self.map_witness(term.2);
                    let c = self.r1cs.new_witness();
                    self.r1cs.add_constraint(
                        &[(FieldElement::one(), a)],
                        &[(FieldElement::one(), b)],
                        &[(FieldElement::one(), c)],
                    );
                    (-noir_to_native(term.0), c)
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let last_term = &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(noir_to_native(last_term.0), self.map_witness(last_term.1))];
            b = vec![(FieldElement::one(), self.map_witness(last_term.2))];
        }

        // Extend with linear combinations
        linear.extend(
            expr.linear_combinations
                .iter()
                .map(|term| (noir_to_native(term.0).neg(), self.map_witness(term.1))),
        );

        // Add constant by multipliying with constant value one.
        linear.push((noir_to_native(expr.q_c).neg(), self.witness_one()));

        // Add a single linear constraint
        // We could avoid this by substituting back into the last multiplication
        // constraint.
        self.r1cs.add_constraint(&a, &b, &linear);
    }

    pub fn add_circuit(&mut self, circuit: &Circuit<NoirElement>) -> Result<()> {
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.add_assert_zero(expr),

                // Brillig is only for witness generation and does not produce constraints.
                Opcode::BrilligCall { .. } => {}

                op => bail!("Unsupported Opcode {op}"),
            }
        }
        Ok(())
    }
}
