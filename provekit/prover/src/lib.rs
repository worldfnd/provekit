#[cfg(test)]
use crate::r1cs::R1CSSolver;
use {
    crate::{
        r1cs::{CompressedLayers, CompressedR1CS},
        whir_r1cs::WhirR1CSProver,
    },
    acir::native_types::{Witness, WitnessMap},
    anyhow::{Context, Result},
    provekit_common::{
        utils::noir_to_native, FieldElement, Groth16Prover, NoirElement, NoirProof, NoirProver,
        Prover, PublicInputs, TranscriptSponge,
    },
    std::mem::size_of,
    tracing::{debug, info_span, instrument},
    whir::transcript::ProverState,
};
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
use {
    bn254_blackbox_solver::Bn254BlackBoxSolver, nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file, noirc_abi::InputMap,
};
#[cfg(not(target_arch = "wasm32"))]
use {
    mavros_vm::interpreter as mavros_interpreter, provekit_common::MavrosProver, std::path::Path,
    whir::transcript::VerifierMessage,
};

pub(crate) mod bigint_mod;
pub(crate) mod ec_arith;
#[cfg(not(target_arch = "wasm32"))]
pub mod input_utils;
pub(crate) mod r1cs;
mod whir_r1cs;
mod witness;

// Public re-exports for items used by integration tests and benchmarks.
pub use {ec_arith::ec_scalar_mul, r1cs::solve_witness_vec};

/// `prove` and `prove_with_toml` are native-only (cfg-gated out on wasm32).
/// `prove_with_witness` is available on all targets. `MavrosProver` does not
/// support `prove_with_witness` (errors at runtime).
pub trait Prove {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<NoirProof>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;

    fn prove_with_witness(self, witness: WitnessMap<NoirElement>) -> Result<NoirProof>;
}

#[instrument(skip_all)]
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
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

#[instrument(skip_all)]
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
fn generate_noir_witness_for_groth16(
    prover: &mut Groth16Prover,
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
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove(mut self, input_map: InputMap) -> Result<NoirProof> {
        let witness = generate_noir_witness(&mut self, input_map)?;
        self.prove_with_witness(witness)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _return_value) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;
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

        drop(self.program);
        drop(self.witness_generator);

        // R1CS matrices are only needed at sumcheck; compress to free memory during
        // commits.
        let compressed_r1cs =
            CompressedR1CS::compress(self.r1cs).context("While compressing R1CS")?;
        let num_witnesses = compressed_r1cs.num_witnesses();
        let num_constraints = compressed_r1cs.num_constraints();

        // Set up transcript with public inputs bound to the instance.
        let instance = public_inputs.hash_bytes(self.hash_config);
        let ds = self
            .whir_for_witness
            .create_domain_separator()
            .instance(&instance);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(self.hash_config));

        // Allocate space for real + virtual witnesses. Virtual witnesses are
        // computation-only (zero entries in A/B/C) but needed by builders.
        let mut witness: Vec<Option<FieldElement>> =
            vec![None; compressed_r1cs.num_witnesses_for_solving()];

        // Solve w1 (or all witnesses if no challenges).
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
                )
                .context("While solving w2 witnesses")?;
            }
            drop(acir_witness_idx_to_value_map);

            let w2 = {
                let _s = info_span!("allocate_w2").entered();
                // Only real w2 witnesses (exclude virtual at the end).
                debug_assert!(
                    self.whir_for_witness.w1_size <= num_witnesses,
                    "w1_size ({}) exceeds num_witnesses ({})",
                    self.whir_for_witness.w1_size,
                    num_witnesses
                );
                witness[self.whir_for_witness.w1_size..num_witnesses]
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
        r1cs.test_witness_satisfaction(
            &witness[..num_witnesses]
                .iter()
                .map(|w| w.unwrap())
                .collect::<Vec<_>>(),
        )
        .context("While verifying R1CS instance")?;

        // Extract only real witnesses (first num_witnesses) for the sumcheck.
        // Virtual witnesses at [num_witnesses, num_witnesses+num_virtual) were
        // needed for builder computation but have zero entries in A/B/C.
        let full_witness: Vec<FieldElement> = witness[..num_witnesses]
            .iter()
            .enumerate()
            .map(|(i, w)| w.ok_or_else(|| anyhow::anyhow!("Witness {i} unsolved after solving")))
            .collect::<Result<Vec<_>>>()?;

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove_noir(merlin, r1cs, commitments, full_witness, &public_inputs)
            .context("While proving R1CS instance")?;

        Ok(NoirProof::Whir {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Prove for MavrosProver {
    #[cfg(feature = "witness-generation")]
    fn prove(mut self, input_map: InputMap) -> Result<NoirProof> {
        provekit_common::register_ntt();

        let params = crate::input_utils::ordered_params_from_btreemap(&self.abi, &input_map)?;
        let phase1 = mavros_interpreter::run_phase1(
            &mut self.witgen_binary,
            self.witness_layout,
            self.constraints_layout,
            &params,
        );

        let num_public_inputs = self.num_public_inputs;
        let public_inputs = if num_public_inputs == 0 {
            PublicInputs::new()
        } else {
            PublicInputs::from_vec(phase1.out_wit_pre_comm[1..=num_public_inputs].to_vec())
        };

        // Set up transcript with public inputs bound to the instance.
        let instance = public_inputs.hash_bytes(self.hash_config);
        let ds = self
            .whir_for_witness
            .create_domain_separator()
            .instance(&instance);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(self.hash_config));

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

        let commitments = if self.whir_for_witness.num_challenges > 0 {
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

            vec![commitment_1, commitment_2]
        } else {
            mavros_interpreter::run_phase2(
                phase1.clone(),
                &[],
                self.witness_layout,
                self.constraints_layout,
            );
            vec![commitment_1]
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

        Ok(NoirProof::Whir {
            public_inputs,
            whir_r1cs_proof,
        })
    }

    #[cfg(feature = "witness-generation")]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let project_path = prover_toml
            .as_ref()
            .parent()
            .context("Could not derive project path from Prover.toml path")?;

        let input_map =
            crate::input_utils::read_prover_inputs(&project_path.to_path_buf(), &self.abi)?;
        self.prove(input_map)
    }

    fn prove_with_witness(self, _witness: WitnessMap<NoirElement>) -> Result<NoirProof> {
        Err(anyhow::anyhow!(
            "prove_with_witness is not supported for Mavros prover"
        ))
    }
}

impl Prove for Groth16Prover {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove(mut self, input_map: InputMap) -> Result<NoirProof> {
        let witness = generate_noir_witness_for_groth16(&mut self, input_map)?;
        self.prove_with_witness(witness)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        let (input_map, _return_value) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;
        self.prove(input_map)
    }

    #[instrument(skip_all)]
    fn prove_with_witness(
        mut self,
        acir_witness_idx_to_value_map: WitnessMap<NoirElement>,
    ) -> Result<NoirProof> {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        // Extract public inputs
        let mut public_input_indices = self.program.functions[0].public_inputs().indices();
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

        let num_witnesses = self.r1cs.num_witnesses();

        // Deserialize Groth16 proving key, then free the serialized bytes
        let pk: provekit_groth16::ProvingKey = {
            let _s = info_span!("deserialize_groth16_pk").entered();
            let pk_bytes = std::mem::take(&mut self.groth16_pk);
            let result =
                CanonicalDeserialize::deserialize_uncompressed_unchecked(&pk_bytes[..])
                    .context("while deserializing Groth16 proving key")?;
            drop(pk_bytes);
            result
        };

        let has_commitments = !self.commitment_info.is_empty();

        // Allocate witness vector
        let mut witness: Vec<Option<FieldElement>> =
            vec![None; self.r1cs.num_witnesses_for_solving()];

        // Create a dummy transcript — Groth16 doesn't use Fiat-Shamir during witness solving
        let dummy_instance: Vec<u8> = Vec::new();
        let ds = whir::transcript::DomainSeparator::protocol(&"groth16-dummy")
            .instance(&dummy_instance);
        let mut dummy_transcript = ProverState::new(&ds, TranscriptSponge::default());

        // --- Phase 1: Solve w1 witnesses (pre-commitment) ---
        {
            let _s = info_span!("solve_groth16_w1").entered();
            crate::r1cs::solve_witness_vec(
                &mut witness,
                self.split_witness_builders.w1_layers,
                &acir_witness_idx_to_value_map,
                &mut dummy_transcript,
            )
            .context("While solving Groth16 w1 witnesses")?;
        }

        // --- Phase 2: BSB22 Pedersen commitment (WHIR-style: one commit, N challenges) ---
        let mut pedersen_commitments: Vec<ark_bn254::G1Affine> = Vec::new();
        let mut committed_values: Vec<Vec<FieldElement>> = Vec::new();
        let mut groth16_ci: Vec<provekit_groth16::CommitmentInfo> = Vec::new();

        if has_commitments {
            let _s = info_span!("groth16_bsb22_commit").entered();

            // One commitment covering all private w1 wires
            let ci = &self.commitment_info[0];

            // Gather private committed witness values
            let private_vals: Vec<FieldElement> = ci
                .private_committed
                .iter()
                .map(|&wire_idx| {
                    witness[wire_idx].ok_or_else(|| {
                        anyhow::anyhow!(
                            "BSB22: private committed wire {wire_idx} not solved before commitment"
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            // Compute Pedersen commitment: C = Σ vᵢ · Basis[i]
            let commitment = pk.commitment_keys[0].commit(&private_vals)?;

            // Gather public values for hashing
            let public_vals: Vec<FieldElement> = ci
                .public_committed
                .iter()
                .map(|&wire_idx| {
                    witness[wire_idx].ok_or_else(|| {
                        anyhow::anyhow!(
                            "BSB22: public wire {wire_idx} not solved before commitment"
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            // Derive N challenges from one commitment via hash_to_fr_multi
            let challenge_data = {
                use ark_serialize::CanonicalSerialize;
                let mut data = Vec::new();
                let mut commitment_bytes = Vec::new();
                commitment
                    .serialize_uncompressed(&mut commitment_bytes)
                    .context("while serializing commitment")?;
                data.extend_from_slice(&commitment_bytes);
                for val in &public_vals {
                    let bytes = provekit_groth16::prover::fr_to_bytes(val);
                    data.extend_from_slice(&bytes);
                }
                data
            };

            let challenges = provekit_groth16::prover::hash_to_fr_multi(
                &challenge_data,
                provekit_groth16::COMMITMENT_DST,
                ci.challenge_indices.len(),
            )?;

            // Insert each challenge into its wire index
            for (challenge, &wire_idx) in challenges.iter().zip(ci.challenge_indices.iter()) {
                witness[wire_idx] = Some(*challenge);
            }

            // Build groth16 CommitmentInfo for the inner prove() call
            // Uses the first challenge index as commitment_index
            groth16_ci.push(provekit_groth16::CommitmentInfo {
                public_and_commitment_committed: ci.public_committed.clone(),
                private_committed: ci.private_committed.clone(),
                commitment_index: ci.challenge_indices[0],
                nb_public_committed: ci.public_committed.len(),
            });

            pedersen_commitments.push(commitment);
            committed_values.push(private_vals);
        }

        // --- Phase 3: Solve w2 witnesses (post-commitment, if any) ---
        if has_commitments {
            let _s = info_span!("solve_groth16_w2").entered();
            crate::r1cs::solve_witness_vec(
                &mut witness,
                self.split_witness_builders.w2_layers,
                &acir_witness_idx_to_value_map,
                &mut dummy_transcript,
            )
            .context("While solving Groth16 w2 witnesses")?;
        }

        // Extract solved witness vector, then free the Option wrapper vec
        let full_witness: Vec<FieldElement> = witness[..num_witnesses]
            .iter()
            .enumerate()
            .map(|(i, w)| w.ok_or_else(|| anyhow::anyhow!("Witness {i} unsolved")))
            .collect::<Result<Vec<_>>>()?;
        drop(witness);
        drop(acir_witness_idx_to_value_map);

        // Compute R1CS solution vectors: A·w, B·w, C·w
        let (mut a_evals, mut b_evals, mut c_evals) = {
            let _s = info_span!("r1cs_matvec").entered();
            let a = self.r1cs.a() * full_witness.as_slice();
            let b = self.r1cs.b() * full_witness.as_slice();
            let c = self.r1cs.c() * full_witness.as_slice();
            (a, b, c)
        };

        // Save values needed later, then free R1CS (~200+ MB of sparse matrices)
        let nb_public = 1 + self.r1cs.num_public_inputs;
        let num_constraints = self.r1cs.num_constraints();
        let challenge_wire_indices: Vec<usize> = self
            .commitment_info
            .iter()
            .flat_map(|ci| ci.challenge_indices.iter().copied())
            .collect();
        drop(self.r1cs);
        drop(self.commitment_info);
        drop(self.program);
        drop(self.witness_generator);

        // Compute quotient polynomial H
        let domain: ark_poly::Radix2EvaluationDomain<FieldElement> =
            ark_poly::EvaluationDomain::new(num_constraints)
                .ok_or_else(|| anyhow::anyhow!("failed to create FFT domain"))?;
        let h = provekit_groth16::prover::compute_h(
            &mut a_evals,
            &mut b_evals,
            &mut c_evals,
            &domain,
        );
        // Free eval buffers no longer needed after compute_h
        drop(a_evals);
        drop(b_evals);
        drop(c_evals);

        // Call Groth16 prover with H and BSB22 data
        let proof = provekit_groth16::prover::prove(
            &pk,
            nb_public,
            &full_witness,
            &h,
            &groth16_ci,
            &committed_values,
            &pedersen_commitments,
            &challenge_wire_indices,
        )
        .context("While generating Groth16 proof")?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .context("while serializing Groth16 proof")?;

        Ok(NoirProof::Groth16 {
            public_inputs,
            groth16_proof: proof_bytes,
        })
    }
}

impl Prove for Prover {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove(input_map),
            Prover::Mavros(p) => p.prove(input_map),
            Prover::Groth16(p) => p.prove(input_map),
        }
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove_with_toml(prover_toml),
            Prover::Mavros(p) => p.prove_with_toml(prover_toml),
            Prover::Groth16(p) => p.prove_with_toml(prover_toml),
        }
    }

    fn prove_with_witness(self, witness: WitnessMap<NoirElement>) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove_with_witness(witness),
            #[cfg(not(target_arch = "wasm32"))]
            Prover::Mavros(p) => p.prove_with_witness(witness),
            #[cfg(target_arch = "wasm32")]
            Prover::Mavros(_) => {
                anyhow::bail!("Mavros prover is not supported on WASM")
            }
            Prover::Groth16(p) => p.prove_with_witness(witness),
        }
    }
}
