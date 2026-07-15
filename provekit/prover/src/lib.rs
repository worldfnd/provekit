#[cfg(test)]
use crate::r1cs::R1CSSolver;
use {
    crate::whir_r1cs::WhirR1CSProver,
    acir::native_types::{Witness, WitnessMap},
    anyhow::{Context, Result},
    provekit_common::{
        utils::noir_to_native, FieldElement, NoirElement, NoirProof, Prover, PublicInputs,
        TranscriptSponge,
    },
    std::mem::size_of,
    tracing::{debug, info_span, instrument},
    whir::transcript::ProverState,
};
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
use {
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    provekit_common::{Format, InputMap},
    std::path::Path,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<NoirProof>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_inputs(self, inputs: &str, format: Format) -> Result<NoirProof>;

    fn prove_with_witness(self, witness: WitnessMap<NoirElement>) -> Result<NoirProof>;
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
    fn prove(mut self, input_map: InputMap) -> Result<NoirProof> {
        let witness = self.generate_witness(input_map)?;
        self.prove_with_witness(witness)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _expected_return) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;
        self.prove(input_map)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_inputs(self, inputs: &str, format: Format) -> Result<NoirProof> {
        let input_map = format
            .parse(inputs, self.witness_generator.abi())
            .with_context(|| format!("While parsing {} inputs", format.ext()))?;
        self.prove(input_map)
    }

    #[instrument(skip_all)]
    fn prove_with_witness(
        self,
        acir_witness_idx_to_value_map: WitnessMap<NoirElement>,
    ) -> Result<NoirProof> {
        provekit_common::register_ntt();

        let mut public_input_indices = self.program.functions[0].public_inputs().indices();
        public_input_indices.sort_unstable();
        let public_inputs = PublicInputs::from_vec(
            public_input_indices
                .iter()
                .map(|&idx| {
                    acir_witness_idx_to_value_map
                        .get(&Witness::from(idx))
                        .map(|v| noir_to_native(*v))
                        .ok_or_else(|| anyhow::anyhow!("Missing public input at index {idx}"))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        drop(self.program);
        drop(self.witness_generator);

        let r1cs = self.r1cs;
        let num_witnesses = r1cs.num_witnesses();
        let num_constraints = r1cs.num_constraints();

        // Set up transcript with public inputs bound to the instance.
        let instance = public_inputs.hash_bytes();
        let ds = self
            .whir_for_witness
            .create_domain_separator()
            .instance(&instance);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::default());

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
            )
            .context("While solving w1 witnesses")?;
        }

        // Hold w2 layers across the w1 commit only when challenges exist.
        let has_challenges = self.whir_for_witness.num_challenges > 0;
        let w2_layers = if has_challenges {
            Some(self.split_witness_builders.w2_layers)
        } else {
            drop(self.split_witness_builders.w2_layers);
            None
        };

        debug!(
            witness_heap_bytes = witness.capacity() * size_of::<Option<FieldElement>>(),
            "component sizes after solve_w1"
        );

        // Verify that ACIR-derived public inputs match the R1CS witness layout.
        debug_assert!(
            {
                let n = public_inputs.0.len();
                n == 0
                    || witness[1..=n]
                        .iter()
                        .zip(public_inputs.0.iter())
                        .all(|(w, pi)| w.map_or(false, |v| v == *pi))
            },
            "Public inputs from ACIR witness map do not match witness[1..=N]"
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
            let w2_layers = w2_layers.expect("w2_layers is Some whenever has_challenges is true");
            {
                let _s = info_span!("solve_w2").entered();
                crate::r1cs::solve_witness_vec(
                    &mut witness,
                    w2_layers,
                    &acir_witness_idx_to_value_map,
                    &mut merlin,
                )
                .context("While solving w2 witnesses")?;
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

        #[cfg(test)]
        r1cs.test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
            .context("While verifying R1CS instance")?;

        let full_witness: Vec<FieldElement> = witness
            .into_iter()
            .enumerate()
            .map(|(i, w)| w.ok_or_else(|| anyhow::anyhow!("Witness {i} unsolved after solving")))
            .collect::<Result<Vec<_>>>()?;

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(merlin, r1cs, commitments, full_witness, &public_inputs)
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}
