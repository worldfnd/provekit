use {
    crate::{r1cs::R1CSSolver, whir_r1cs::WhirR1CSProver},
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    provekit_common::{
        skyscraper::SkyscraperSponge, utils::noir_to_native, FieldElement, IOPattern, NoirElement,
        NoirProof, Prover,
    },
    spongefish::{codecs::arkworks_algebra::FieldToUnitSerialize, ProverState},
    tracing::instrument,
};
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
use {
    bn254_blackbox_solver::Bn254BlackBoxSolver, nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file, noirc_abi::InputMap, std::path::Path,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;

    /// Generate a proof from a pre-computed witness map.
    ///
    /// This method is WASM-compatible and does not require witness generation
    /// dependencies. The witness should be generated externally (e.g., using
    /// @noir-lang/noir_js in the browser).
    fn prove_with_witness(self, witness: WitnessMap<NoirElement>) -> Result<NoirProof>;

    fn create_witness_io_pattern(&self) -> IOPattern;

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        witness: &WitnessMap<NoirElement>,
    ) -> Result<()>;
}

impl Prove for Prover {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
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

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
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

        // Solve w1 (or all witnesses if no challenges)
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

        let commitment_1 = self
            .whir_for_witness
            .commit(&mut merlin, &self.r1cs, w1, true)
            .context("While committing to w1")?;

        // Build commitment list based on whether we have challenges
        let commitments = if self.whir_for_witness.num_challenges > 0 {
            // Solve w2
            self.r1cs.solve_witness_vec(
                &mut witness,
                self.split_witness_builders.w2_layers,
                &acir_witness_idx_to_value_map,
                &mut merlin,
            );

            let w2 = witness[self.whir_for_witness.w1_size..]
                .iter()
                .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
                .collect::<Result<Vec<_>>>()?;

            let commitment_2 = self
                .whir_for_witness
                .commit(&mut merlin, &self.r1cs, w2, false)
                .context("While committing to w2")?;

            vec![commitment_1, commitment_2]
        } else {
            vec![commitment_1]
        };
        drop(acir_witness_idx_to_value_map);

        #[cfg(test)]
        self.r1cs
            .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
            .context("While verifying R1CS instance")?;
        drop(witness);

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(merlin, self.r1cs, commitments)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }

    #[instrument(skip_all)]
    fn prove_with_witness(
        self,
        acir_witness_idx_to_value_map: WitnessMap<NoirElement>,
    ) -> Result<NoirProof> {
        // Set up transcript
        let io: IOPattern = self.whir_for_witness.create_io_pattern();
        let mut merlin = io.to_prover_state();
        drop(io);

        let mut witness: Vec<Option<FieldElement>> = vec![None; self.r1cs.num_witnesses()];

        // Solve w1 (or all witnesses if no challenges)
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

        let commitment_1 = self
            .whir_for_witness
            .commit(&mut merlin, &self.r1cs, w1, true)
            .context("While committing to w1")?;

        // Build commitment list based on whether we have challenges
        let commitments = if self.whir_for_witness.num_challenges > 0 {
            // Solve w2
            self.r1cs.solve_witness_vec(
                &mut witness,
                self.split_witness_builders.w2_layers,
                &acir_witness_idx_to_value_map,
                &mut merlin,
            );

            let w2 = witness[self.whir_for_witness.w1_size..]
                .iter()
                .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
                .collect::<Result<Vec<_>>>()?;

            let commitment_2 = self
                .whir_for_witness
                .commit(&mut merlin, &self.r1cs, w2, false)
                .context("While committing to w2")?;

            vec![commitment_1, commitment_2]
        } else {
            vec![commitment_1]
        };
        drop(acir_witness_idx_to_value_map);

        // Verify witness (redundant with solve)
        #[cfg(test)]
        self.r1cs
            .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
            .context("While verifying R1CS instance")?;
        drop(witness);

        // Prove R1CS instance
        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(merlin, self.r1cs, commitments)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }

    fn create_witness_io_pattern(&self) -> IOPattern {
        // Use the same IO pattern as the WHIR R1CS scheme
        self.whir_for_witness.create_io_pattern()
    }

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        witness: &WitnessMap<NoirElement>,
    ) -> Result<()> {
        // Absorb circuit shape
        let _ = merlin.add_scalars(&[
            FieldElement::from(self.r1cs.num_constraints() as u64),
            FieldElement::from(self.r1cs.num_witnesses() as u64),
        ]);

        // Absorb public inputs (values) in canonical order
        let circuit = &self.program.functions[0];
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
