use {
    crate::{
        r1cs::R1CSSolver,
        whir_r1cs::WhirR1CSProver,
        witness::{fill_witness, witness_io_pattern::WitnessIOPattern},
    },
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{
        skyscraper::SkyscraperSponge, utils::noir_to_native, witness::WitnessBuilder, FieldElement,
        IOPattern, NoirElement, NoirProof, Prover,
    },
    spongefish::{codecs::arkworks_algebra::FieldToUnitSerialize, ProverState},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(&mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;

    fn create_witness_io_pattern(&self) -> IOPattern;

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        witness: &WitnessMap<NoirElement>,
    ) -> Result<()>;
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

        let initial_witness = self
            .witness_generator
            .take()
            .unwrap()
            .abi()
            .encode(&input_map, None)?;

        let mut witness_stack = nargo::ops::execute_program(
            &self.program.as_ref().unwrap(),
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
    fn prove(&mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _expected_return) = read_inputs_from_file(
            prover_toml.as_ref(),
            self.witness_generator.as_ref().unwrap().abi(),
        )?;

        let acir_witness_idx_to_value_map = self.generate_witness(input_map)?;

        // Solve R1CS instance
        let witness_io = self.create_witness_io_pattern();
        let mut witness_merlin = witness_io.to_prover_state();
        self.seed_witness_merlin(&mut witness_merlin, &acir_witness_idx_to_value_map)?;

        let partial_witness = self.r1cs.as_ref().unwrap().solve_witness_vec(
            self.layered_witness_builders.take().unwrap(),
            acir_witness_idx_to_value_map,
            &mut witness_merlin,
        );
        let witness = fill_witness(partial_witness).context("while filling witness")?;

        // Verify witness (redudant with solve)
        #[cfg(test)]
        self.r1cs
            .as_ref()
            .unwrap()
            .test_witness_satisfaction(&witness)
            .context("While verifying R1CS instance")?;

        // Prove R1CS instance
        let whir_r1cs_proof = self
            .whir_for_witness
            .take()
            .unwrap()
            .prove(self.r1cs.take().unwrap(), witness)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }

    fn create_witness_io_pattern(&self) -> IOPattern {
        let circuit = &self.program.as_ref().unwrap().functions[0];
        let public_idxs = circuit.public_inputs().indices();
        let num_challenges = self
            .layered_witness_builders
            .as_ref()
            .unwrap()
            .layers
            .iter()
            .flat_map(|layer| &layer.witness_builders)
            .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
            .count();

        // Create witness IO pattern
        IOPattern::new("📜")
            .add_shape()
            .add_public_inputs(public_idxs.len())
            .add_logup_challenges(num_challenges)
    }

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        witness: &WitnessMap<NoirElement>,
    ) -> Result<()> {
        // Absorb circuit shape
        let _ = merlin.add_scalars(&[
            FieldElement::from(self.r1cs.as_ref().unwrap().num_constraints() as u64),
            FieldElement::from(self.r1cs.as_ref().unwrap().num_witnesses() as u64),
        ]);

        // Absorb public inputs (values) in canonical order
        let circuit = &self.program.take().unwrap().functions[0];
        let public_idxs = circuit.public_inputs().indices();
        if !public_idxs.is_empty() {
            let pub_vals: Vec<FieldElement> = public_idxs
                .iter()
                .map(|&i| noir_to_native(*witness.get_index(i).expect("missing public input")))
                .collect();
            let _ = merlin.add_scalars(&pub_vals);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
