#[cfg(test)]
use crate::r1cs::R1CSSolver;
use {
    crate::{
        r1cs::{CompressedLayers, CompressedR1CS},
        whir_r1cs::WhirR1CSProver,
    },
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    mavros_vm::interpreter as mavros_interpreter,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{
        FieldElement, MavrosProver, NoirElement, NoirProof, NoirProver, Prover, PublicInputs,
        TranscriptSponge,
    },
    std::{mem::size_of, path::Path},
    tracing::{debug, info_span, instrument},
    whir::transcript::{codecs::Empty, ProverState, VerifierMessage},
};

pub mod input_utils;
mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

#[instrument(skip_all)]
fn generate_noir_witness(
    prover: &mut NoirProver,
    input_map: InputMap,
) -> Result<WitnessMap<NoirElement>> {
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

    let initial_witness = prover.witness_generator.abi().encode(&input_map, None)?;

    let mut witness_stack = nargo::ops::execute_program(
        &prover.program,
        initial_witness,
        &solver,
        &mut foreign_call_executor,
    )?;

    Ok(witness_stack
        .pop()
        .context("Missing witness results")?
        .witness)
}

impl Prove for NoirProver {
    #[instrument(skip_all)]
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        provekit_common::register_ntt();

        let (input_map, _expected_return) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;

        let acir_witness_idx_to_value_map = generate_noir_witness(&mut self, input_map)?;
        let num_public_inputs = self.program.functions[0].public_inputs().indices().len();
        drop(self.program);
        drop(self.witness_generator);

        // R1CS matrices are only needed at sumcheck; compress to free memory during
        // commits.
        let compressed_r1cs =
            CompressedR1CS::compress(self.r1cs).context("While compressing R1CS")?;
        let num_witnesses = compressed_r1cs.num_witnesses();
        let num_constraints = compressed_r1cs.num_constraints();

        // Set up transcript with sponge selected by hash_config.
        let ds = self
            .whir_for_witness
            .create_domain_separator()
            .instance(&Empty);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(self.hash_config));

        let mut witness: Vec<Option<FieldElement>> = vec![None; num_witnesses];

        // Solve w1 (or all witnesses if no challenges).
        // Outer span captures memory AFTER w1_layers parameter is freed
        // (parameter drop happens before outer span close).
        {
            let _s = info_span!("solve_w1").entered();
            crate::r1cs::solve_witness_vec(
                &mut witness,
                self.split_witness_builders.w1_layers,
                &acir_witness_idx_to_value_map,
                &mut merlin,
            );
        }

        // Compress w2 layers to free memory during w1 commit (only when
        // challenges exist; otherwise just drop them).
        let has_challenges = self.whir_for_witness.num_challenges > 0;
        let compressed_w2_layers = if has_challenges {
            Some(
                CompressedLayers::compress(self.split_witness_builders.w2_layers)
                    .context("While compressing w2 layers")?,
            )
        } else {
            drop(self.split_witness_builders.w2_layers);
            None
        };

        debug!(
            witness_heap_bytes = witness.capacity() * size_of::<Option<FieldElement>>(),
            compressed_r1cs_blob_bytes = compressed_r1cs.blob_len(),
            "component sizes after solve_w1"
        );

        let w1 = {
            let _s = info_span!("allocate_w1").entered();
            witness[..self.whir_for_witness.w1_size]
                .iter()
                .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
                .collect::<Result<Vec<_>>>()?
        };

        let commitment_1 = self
            .whir_for_witness
            .commit(&mut merlin, num_witnesses, num_constraints, w1, true)
            .context("While committing to w1")?;

        let commitments = if has_challenges {
            let w2_layers = compressed_w2_layers
                .unwrap()
                .decompress()
                .context("While decompressing w2 layers")?;
            {
                let _s = info_span!("solve_w2").entered();
                crate::r1cs::solve_witness_vec(
                    &mut witness,
                    w2_layers,
                    &acir_witness_idx_to_value_map,
                    &mut merlin,
                );
            }
            drop(acir_witness_idx_to_value_map);

            let w2 = {
                let _s = info_span!("allocate_w2").entered();
                witness[self.whir_for_witness.w1_size..]
                    .iter()
                    .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
                    .collect::<Result<Vec<_>>>()?
            };

            let commitment_2 = self
                .whir_for_witness
                .commit(&mut merlin, num_witnesses, num_constraints, w2, false)
                .context("While committing to w2")?;

            vec![commitment_1, commitment_2]
        } else {
            drop(acir_witness_idx_to_value_map);
            vec![commitment_1]
        };

        // Decompress R1CS for the sumcheck and matrix operations.
        let r1cs = compressed_r1cs
            .decompress()
            .context("While decompressing R1CS")?;

        #[cfg(test)]
        r1cs.test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
            .context("While verifying R1CS instance")?;

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

        let full_witness: Vec<FieldElement> = witness
            .into_iter()
            .enumerate()
            .map(|(i, w)| w.ok_or_else(|| anyhow::anyhow!("Witness {i} unsolved after solving")))
            .collect::<Result<Vec<_>>>()?;

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove_noir(merlin, r1cs, commitments, full_witness, &public_inputs)
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}

impl Prove for MavrosProver {
    #[instrument(skip_all)]
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        provekit_common::register_ntt();

        let project_path = prover_toml
            .as_ref()
            .parent()
            .context("Could not derive project path from Prover.toml path")?;

        let params =
            crate::input_utils::read_prover_inputs(&project_path.to_path_buf(), &self.abi)?;

        let phase1 = mavros_interpreter::run_phase1(
            &mut self.witgen_binary,
            self.witness_layout,
            self.constraints_layout,
            &params,
        );

        let ds = self
            .whir_for_witness
            .create_domain_separator()
            .instance(&Empty);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::default());

        let commitment_1 = self
            .whir_for_witness
            .commit(
                &mut merlin,
                self.witness_layout.size(),
                self.constraints_layout.algebraic_size,
                phase1.out_wit_pre_comm.clone(),
                true,
            )
            .context("While committing to w1")?;

        let (commitments, witgen_result) = if self.whir_for_witness.num_challenges > 0 {
            let challenges: Vec<FieldElement> = (0..self.witness_layout.challenges_size)
                .map(|_| merlin.verifier_message())
                .collect();

            let witgen_result = mavros_interpreter::run_phase2(
                phase1.clone(),
                &challenges,
                self.witness_layout,
                self.constraints_layout,
            );

            let commitment_2 = self
                .whir_for_witness
                .commit(
                    &mut merlin,
                    self.witness_layout.size(),
                    self.constraints_layout.algebraic_size,
                    witgen_result.out_wit_post_comm.clone(),
                    false,
                )
                .context("While committing to w2")?;

            (vec![commitment_1, commitment_2], witgen_result)
        } else {
            let witgen_result = mavros_interpreter::run_phase2(
                phase1.clone(),
                &[],
                self.witness_layout,
                self.constraints_layout,
            );
            (vec![commitment_1], witgen_result)
        };

        let num_public_inputs = self.num_public_inputs;
        let public_inputs = if num_public_inputs == 0 {
            PublicInputs::new()
        } else {
            PublicInputs::from_vec(witgen_result.out_wit_pre_comm[1..=num_public_inputs].to_vec())
        };

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove_mavros(
                merlin,
                phase1,
                commitments,
                &public_inputs,
                self.witness_layout,
                self.constraints_layout,
                &self.ad_binary,
            )
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}

impl Prove for Prover {
    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove(prover_toml),
            Prover::Mavros(p) => p.prove(prover_toml),
        }
    }
}

#[cfg(test)]
mod tests {}
