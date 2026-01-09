use {
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{hash::HashFunction, FieldElement, NoirElement, NoirProof, Prover},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

use crate::r1cs::R1CSSolver;

pub trait Prove {
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

/// Macro to generate prover dispatch for each hash type
macro_rules! impl_prove_for_hash {
    ($prover:expr, $acir_map:expr, $prover_mod:path) => {{
        use $prover_mod as prover_mod;

        // Set up transcript with correct sponge type
        let io = prover_mod::create_io_pattern(&$prover.whir_for_witness);
        let mut merlin = io.to_prover_state();
        drop(io);

        let mut witness: Vec<Option<FieldElement>> = vec![None; $prover.r1cs.num_witnesses()];

        // Solve w1 (or all witnesses if no challenges)
        $prover.r1cs.solve_witness_vec(
            &mut witness,
            $prover.split_witness_builders.w1_layers,
            &$acir_map,
            &mut merlin,
        );

        let w1 = witness[..$prover.whir_for_witness.w1_size]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
            .collect::<Result<Vec<_>>>()?;

        let commitment_1 = prover_mod::commit(
            &$prover.whir_for_witness,
            &mut merlin,
            &$prover.r1cs,
            w1,
            true,
        )
        .context("While committing to w1")?;

        // Build commitment list based on whether we have challenges
        let commitments = if $prover.whir_for_witness.num_challenges > 0 {
            // Solve w2
            $prover.r1cs.solve_witness_vec(
                &mut witness,
                $prover.split_witness_builders.w2_layers,
                &$acir_map,
                &mut merlin,
            );

            let w2 = witness[$prover.whir_for_witness.w1_size..]
                .iter()
                .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
                .collect::<Result<Vec<_>>>()?;

            let commitment_2 = prover_mod::commit(
                &$prover.whir_for_witness,
                &mut merlin,
                &$prover.r1cs,
                w2,
                false,
            )
            .context("While committing to w2")?;

            vec![commitment_1, commitment_2]
        } else {
            vec![commitment_1]
        };
        drop($acir_map);

        #[cfg(test)]
        $prover
            .r1cs
            .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
            .context("While verifying R1CS instance")?;
        drop(witness);

        let whir_r1cs_proof =
            prover_mod::prove(&$prover.whir_for_witness, merlin, $prover.r1cs, commitments)
                .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }};
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

        // Dispatch to the appropriate prover based on hash function
        match self.whir_for_witness.hash_function {
            HashFunction::Skyscraper => impl_prove_for_hash!(
                self,
                acir_witness_idx_to_value_map,
                crate::whir_r1cs::skyscraper_prover
            ),
            HashFunction::Sha2 => impl_prove_for_hash!(
                self,
                acir_witness_idx_to_value_map,
                crate::whir_r1cs::sha2_prover
            ),
            HashFunction::Sha3 => impl_prove_for_hash!(
                self,
                acir_witness_idx_to_value_map,
                crate::whir_r1cs::sha3_prover
            ),
            HashFunction::Blake3 => impl_prove_for_hash!(
                self,
                acir_witness_idx_to_value_map,
                crate::whir_r1cs::blake3_prover
            ),
        }
    }
}

#[cfg(test)]
mod tests {}
