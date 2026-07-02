//! Zinc+ proving path: solve the witness with the existing layered solver,
//! then prove the R1CS instance with the Zinc+ backend instead of WHIR.
//!
//! Only challenge-free circuits are supported: all witnesses must solve in
//! the w1 layers without squeezing Fiat-Shamir challenges (range checks,
//! lookups, RAM and bin-ops introduce challenges and are rejected).

use {
    crate::Prove,
    acir::native_types::{Witness, WitnessMap},
    anyhow::{ensure, Context, Result},
    provekit_common::{
        utils::noir_to_native, FieldElement, NoirElement, NoirProof, PublicInputs,
        TranscriptSponge, WhirR1CSProof, ZincPlusProver,
    },
    tracing::{info_span, instrument},
    whir::transcript::ProverState,
};
#[cfg(feature = "witness-generation")]
use {noir_artifact_cli::fs::inputs::read_inputs_from_file, noirc_abi::InputMap, std::path::Path};

impl Prove for ZincPlusProver {
    #[cfg(feature = "witness-generation")]
    #[instrument(skip_all)]
    fn prove(mut self, input_map: InputMap) -> Result<NoirProof> {
        let witness = crate::generate_noir_witness(&mut self.0, input_map)?;
        self.prove_with_witness(witness)
    }

    #[cfg(feature = "witness-generation")]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _return_value) =
            read_inputs_from_file(prover_toml.as_ref(), self.0.witness_generator.abi())?;
        self.prove(input_map)
    }

    #[instrument(skip_all)]
    fn prove_with_witness(
        self,
        acir_witness_idx_to_value_map: WitnessMap<NoirElement>,
    ) -> Result<NoirProof> {
        let prover = self.0;

        // Defense in depth: `NoirProofScheme::into_zinc_plus` already rejects
        // challenge-bearing circuits at prepare time.
        ensure!(
            prover.whir_for_witness.num_challenges == 0
                && prover.split_witness_builders.w2_layers.builders_len() == 0,
            "the Zinc+ backend supports only challenge-free circuits; this circuit requires {} \
             Fiat-Shamir challenge(s)",
            prover.whir_for_witness.num_challenges,
        );

        // Extract public inputs from the solved ACIR witness (same as the
        // WHIR path).
        let mut public_input_indices = prover.program.functions[0].public_inputs().indices();
        public_input_indices.sort_unstable();
        let public_inputs = if public_input_indices.is_empty() {
            PublicInputs::new()
        } else {
            let values = public_input_indices
                .iter()
                .map(|&idx| {
                    let noir_val = acir_witness_idx_to_value_map
                        .get(&Witness::from(idx))
                        .ok_or_else(|| anyhow::anyhow!("Missing public input at index {idx}"))?;
                    Ok(noir_to_native(*noir_val))
                })
                .collect::<Result<Vec<_>>>()?;
            PublicInputs::from_vec(values)
        };

        // The witness solver takes a transcript, but with zero challenges it
        // is never squeezed; reuse the WHIR domain separator construction so
        // no new transcript concepts are introduced.
        let instance = public_inputs.hash_bytes(prover.hash_config);
        let ds = prover
            .whir_for_witness
            .create_domain_separator()
            .instance(&instance);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(prover.hash_config));

        let mut witness: Vec<Option<FieldElement>> =
            vec![None; prover.r1cs.num_witnesses_for_solving()];
        {
            let _s = info_span!("solve_witness").entered();
            crate::r1cs::solve_witness_vec(
                &mut witness,
                prover.split_witness_builders.w1_layers,
                &acir_witness_idx_to_value_map,
                &mut merlin,
            )
            .context("While solving witnesses")?;
        }
        drop(acir_witness_idx_to_value_map);

        // Real witnesses only (virtual solver-only columns are not part of
        // the matrices and are not committed).
        let full_witness = witness[..prover.r1cs.num_witnesses()]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses are missing")))
            .collect::<Result<Vec<_>>>()?;

        let proof_bytes = {
            let _s = info_span!("zinc_prove").entered();
            provekit_zinc_backend::zinc_prove(&prover.r1cs, &public_inputs.0, &full_witness)
                .context("While proving R1CS instance with Zinc+")?
        };

        // Zinc+ proof bytes ride in the WHIR proof container (`narg_string`),
        // keeping the `NoirProof` wire format unchanged. The verifier
        // dispatches on `Verifier::whir_for_witness == None`.
        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof: WhirR1CSProof {
                narg_string: proof_bytes,
                hints: Vec::new(),
                #[cfg(debug_assertions)]
                pattern: Vec::new(),
            },
        })
    }
}
