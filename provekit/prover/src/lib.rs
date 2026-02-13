use {
    crate::{r1cs::R1CSSolver, whir_r1cs::WhirR1CSProver},
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    mavros::{api as mavros_api, compiled_artifacts::CompiledArtifacts},
    provekit_common::{FieldElement, IOPattern, NoirElement, NoirProof, Prover, PublicInputs},
    std::path::Path,
    tracing::instrument,
};

#[cfg(feature = "mavros_compiler")]
pub mod input_utils;
mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    #[cfg(not(feature = "mavros_compiler"))]
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

impl Prove for Prover {
    #[cfg(not(feature = "mavros_compiler"))]
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

    #[cfg(not(feature = "mavros_compiler"))]
    #[instrument(skip_all)]
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _expected_return) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;

        let acir_witness_idx_to_value_map = self.generate_witness(input_map)?;
        let acir_public_inputs = self.program.functions[0].public_inputs().indices();

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

        // Gather public inputs from witness
        let num_public_inputs = acir_public_inputs.len();
        let public_inputs = if num_public_inputs == 0 {
            PublicInputs::new()
        } else {
            PublicInputs::from_vec(
                witness[1..=num_public_inputs]
                    .iter()
                    .map(|w| w.ok_or_else(|| anyhow::anyhow!("Missing public input witness")))
                    .collect::<Result<Vec<FieldElement>>>()?,
            )
        };
        drop(witness);

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(merlin, self.r1cs, commitments, &public_inputs)
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }

    #[cfg(feature = "mavros_compiler")]
    #[instrument(skip_all)]
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        use provekit_common::utils::convert_mavros_r1cs_to_provekit;

        // Derive the project directory from the Prover.toml path.
        let project_path = prover_toml
            .as_ref()
            .parent()
            .context("Could not derive project path from Prover.toml path")?;

        // let (driver, _) = mavros_api::compile_to_r1cs(project_path.to_path_buf(),
        // false)?;
        let params =
            crate::input_utils::read_prover_inputs(&project_path.to_path_buf(), &self.abi)?;

        let phase1 = mavros_api::run_witgen_phase1(
            &mut self.artifacts.witgen_binary,
            &self.artifacts.r1cs,
            &params,
        );

        // Set up transcript
        let io: IOPattern = self.whir_for_witness.create_io_pattern();
        let mut merlin = io.to_prover_state();
        drop(io);

        // Commit to w1 (pre-commitment witness).
        let commitment_1 = self
            .whir_for_witness
            .commit(
                &mut merlin,
                &self.r1cs,
                phase1.out_wit_pre_comm.clone(),
                true,
            )
            .context("While committing to w1")?;

        let (commitments, witgen_result) = if self.whir_for_witness.num_challenges > 0 {
            use {ark_ff::AdditiveGroup, spongefish::codecs::arkworks_algebra::UnitToField};

            let mut challenges =
                vec![FieldElement::ZERO; self.artifacts.r1cs.witness_layout.challenges_size];
            merlin
                .fill_challenge_scalars(&mut challenges)
                .expect("Failed to extract challenge scalars from Merlin");

            let witgen_result =
                mavros_api::run_witgen_phase2(phase1, &challenges, &self.artifacts.r1cs);

            let commitment_2 = self
                .whir_for_witness
                .commit(
                    &mut merlin,
                    &self.r1cs,
                    witgen_result.out_wit_post_comm.clone(),
                    false,
                )
                .context("While committing to w2")?;

            (vec![commitment_1, commitment_2], witgen_result)
        } else {
            // No challenges: complete phase 2 with empty challenges.
            let witgen_result = mavros_api::run_witgen_phase2(phase1, &[], &self.artifacts.r1cs);
            (vec![commitment_1], witgen_result)
        };

        let num_public_inputs = self.program.functions[0].public_inputs().indices().len();
        let public_inputs = if num_public_inputs == 0 {
            PublicInputs::new()
        } else {
            PublicInputs::from_vec(witgen_result.out_wit_pre_comm[1..=num_public_inputs].to_vec())
        };

        #[cfg(test)]
        assert!(mavros_api::check_witgen(
            &self.artifacts.r1cs,
            &witgen_result
        ));

        let converted_r1cs = convert_mavros_r1cs_to_provekit(&self.artifacts.r1cs);

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(
                merlin,
                converted_r1cs,
                commitments,
                &public_inputs,
                &mut self.artifacts,
            )
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}

#[cfg(test)]
mod tests {}
