use {
    crate::{r1cs::R1CSSolver, whir_r1cs::WhirR1CSProver},
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{FieldElement, IOPattern, NoirElement, NoirProof, Prover},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

impl Prove for Prover {
    #[instrument(skip_all)]
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>> {
        let solver = Bn254BlackBoxSolver::default();
        let mut output_buffer = Vec::new();
        let mut foreign_call_executor = DefaultForeignCallBuilder {
            output:       &mut output_buffer,
            enable_mocks: false,
            resolver_url: None,
            root_path:    None,
            package_name: None,
        }
        .build();

        let initial_witness = self.witness_generator.abi().encode(&input_map, None)?;

        let mut witness_stack = nargo::ops::execute_program(
            &self.program,
            initial_witness,
            &solver,
            &mut foreign_call_executor,
        )?;

        Ok(witness_stack
            .pop()
            .context("Missing witness results")?
            .witness)
    }

    #[instrument(skip_all)]
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _expected_return) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;

        let acir_witness_idx_to_value_map = self.generate_witness(input_map)?;

        // Set up transcript
        let io: IOPattern = self.whir_for_witness.create_io_pattern();
        let mut merlin = io.to_prover_state();
        drop(io);

        let mut witness: Vec<Option<FieldElement>> = vec![None; self.r1cs.num_witnesses()];

        // Solve w1
        self.r1cs.solve_witness_vec(
            &mut witness,
            self.split_witness_builders.w1_layers,
            &acir_witness_idx_to_value_map,
            &mut merlin,
        );
        let w1 = witness[..self.whir_for_witness.w1_size]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
            .collect::<Result<Vec<_>>>()?;

        // Commit to w1
        let commitment_1 = self
            .whir_for_witness
            .commit(&mut merlin, &self.r1cs, w1, true)
            .context("While committing to witness")?;

        // Solve w2
        self.r1cs.solve_witness_vec(
            &mut witness,
            self.split_witness_builders.w2_layers,
            &acir_witness_idx_to_value_map,
            &mut merlin,
        );
        let w2 = witness[self.whir_for_witness.w1_size..]
            .into_iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
            .collect::<Result<Vec<_>>>()?;
        drop(acir_witness_idx_to_value_map);

        // Commit to w2
        let commitment_2 = self
            .whir_for_witness
            .commit(&mut merlin, &self.r1cs, w2, false)
            .context("While committing to witness")?;

        // Verify witness (redudant with solve)
        #[cfg(test)]
        {
            self.r1cs
                .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
                .context("While verifying R1CS instance")?;
        }
        drop(witness);

        // Prove R1CS instance
        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(merlin, self.r1cs, commitment_1, commitment_2)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }
}

#[cfg(test)]
mod tests {}
