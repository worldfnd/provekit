#[cfg(not(target_arch = "wasm32"))]
use crate::mavros_prove::MavrosR1CSProver;
#[cfg(test)]
use crate::solver::R1CSSolver;
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::MavrosProver, mavros_vm::interpreter as mavros_interpreter, std::path::Path,
    whir::transcript::VerifierMessage,
};
use {
    crate::{
        noir_to_native, spark::SparkQueryBatch, Bn254Field, CompressedLayers, FieldElement,
        NoirElement, NoirProver, ProvekitProof, Prover, TranscriptSponge,
    },
    ::tracing::{debug, info, info_span, instrument},
    acir::native_types::{Witness, WitnessMap},
    anyhow::{Context, Result},
    provekit_common::{log_commit_input, CompressedR1CS, PublicInputs, PublicInputsHash},
    provekit_prover::WhirR1CSProver,
    std::mem::{size_of, take},
    whir::transcript::ProverState,
};
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
use {
    bn254_blackbox_solver::Bn254BlackBoxSolver, nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file, noirc_abi::InputMap,
};

/// `prove` and `prove_with_toml` are native-only (cfg-gated out on wasm32).
/// `prove_with_witness` is available on all targets. `MavrosProver` does not
/// support `prove_with_witness` (errors at runtime).
///
/// Callers that also need the SPARK query batch (produced as a side output)
/// use [`prove_with_spark_toml`](Prove::prove_with_spark_toml), which returns
/// the proof and the batch together.
pub trait Prove {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<ProvekitProof<Bn254Field>>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<ProvekitProof<Bn254Field>>;

    fn prove_with_witness(
        self,
        witness: WitnessMap<NoirElement>,
    ) -> Result<ProvekitProof<Bn254Field>>;

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_spark_toml(
        self,
        prover_toml: impl AsRef<Path>,
    ) -> Result<(ProvekitProof<Bn254Field>, SparkQueryBatch)>;
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

impl Prove for NoirProver {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove(mut self, input_map: InputMap) -> Result<ProvekitProof<Bn254Field>> {
        let witness = generate_noir_witness(&mut self, input_map)?;
        self.prove_with_witness(witness)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<ProvekitProof<Bn254Field>> {
        let (input_map, _return_value) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;
        self.prove(input_map)
    }

    #[instrument(skip_all)]
    fn prove_with_witness(
        self,
        witness: WitnessMap<NoirElement>,
    ) -> Result<ProvekitProof<Bn254Field>> {
        let (proof, _) = prove_noir_inner(self, witness, false)?;
        Ok(proof)
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    #[instrument(skip_all)]
    fn prove_with_spark_toml(
        mut self,
        prover_toml: impl AsRef<Path>,
    ) -> Result<(ProvekitProof<Bn254Field>, SparkQueryBatch)> {
        let (input_map, _return_value) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;
        let witness = generate_noir_witness(&mut self, input_map)?;
        let (proof, batch) = prove_noir_inner(self, witness, true)?;
        let batch = batch
            .ok_or_else(|| anyhow::anyhow!("SPARK query batch must be produced when requested"))?;
        Ok((proof, batch))
    }
}

#[instrument(skip_all)]
fn prove_noir_inner(
    prover: NoirProver,
    acir_witness_idx_to_value_map: WitnessMap<NoirElement>,
    produce_spark_query: bool,
) -> Result<(ProvekitProof<Bn254Field>, Option<SparkQueryBatch>)> {
    crate::register();

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

    drop(prover.program);
    drop(prover.witness_generator);

    // R1CS matrices are only needed at sumcheck; compress to free memory during
    // commits.
    let compressed_r1cs =
        CompressedR1CS::compress(prover.r1cs).context("While compressing R1CS")?;
    let num_witnesses = compressed_r1cs.num_witnesses();
    let num_constraints = compressed_r1cs.num_constraints();

    // Set up transcript with public inputs bound to the instance.
    let instance = public_inputs.hash_bytes::<Bn254Field>(prover.hash_config);
    let ds = prover
        .whir_for_witness
        .create_domain_separator()
        .instance(&instance);

    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(prover.hash_config));

    // Allocate space for real + virtual witnesses. Virtual witnesses are
    // computation-only (zero entries in A/B/C) but needed by builders.
    let mut witness: Vec<Option<FieldElement>> =
        vec![None; compressed_r1cs.num_witnesses_for_solving()];

    // Solve w1 (or all witnesses if no challenges).
    {
        let _s = info_span!("solve_w1").entered();
        crate::solver::solve_witness_vec(
            &mut witness,
            prover.split_witness_builders.w1_layers,
            &acir_witness_idx_to_value_map,
            &mut merlin,
        )
        .context("While solving w1 witnesses")?;
    }

    // Compress w2 layers to free memory during w1 commit (only when
    // challenges exist; otherwise just drop them).
    let has_challenges = prover.whir_for_witness.num_challenges > 0;
    let compressed_w2_layers = if has_challenges {
        Some(
            CompressedLayers::compress(prover.split_witness_builders.w2_layers)
                .context("While compressing w2 layers")?,
        )
    } else {
        drop(prover.split_witness_builders.w2_layers);
        None
    };

    debug!(
        witness_heap_bytes = witness.capacity() * size_of::<Option<FieldElement>>(),
        compressed_r1cs_blob_bytes = compressed_r1cs.blob_len(),
        "component sizes after solve_w1"
    );

    let w1 = {
        let _s = info_span!("allocate_w1").entered();
        witness[..prover.whir_for_witness.w1_size]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
            .collect::<Result<Vec<_>>>()?
    };

    log_commit_input("noir_w1", &w1, prover.whir_for_witness.domain_size());
    let commitment_1 = prover
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
            crate::solver::solve_witness_vec(
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
                prover.whir_for_witness.w1_size <= num_witnesses,
                "w1_size ({}) exceeds num_witnesses ({})",
                prover.whir_for_witness.w1_size,
                num_witnesses
            );
            witness[prover.whir_for_witness.w1_size..num_witnesses]
                .iter()
                .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
                .collect::<Result<Vec<_>>>()?
        };

        log_commit_input("noir_w2", &w2, prover.whir_for_witness.domain_size());
        let commitment_2 = prover
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

    let (whir_r1cs_proof, r1cs_spark_queries) = if produce_spark_query {
        let (proof, queries) = prover
            .whir_for_witness
            .prove_noir_with_spark(merlin, r1cs, commitments, full_witness, &public_inputs)
            .context("While proving R1CS instance")?;
        (proof, Some(SparkQueryBatch::from(queries)))
    } else {
        let proof = prover
            .whir_for_witness
            .prove_noir(merlin, r1cs, commitments, full_witness, &public_inputs)
            .context("While proving R1CS instance")?;
        (proof, None)
    };

    Ok((
        ProvekitProof {
            public_inputs,
            whir_r1cs_proof,
        },
        r1cs_spark_queries,
    ))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "witness-generation"))]
fn prove_mavros_inner(
    prover: MavrosProver,
    input_map: InputMap,
    produce_spark_query: bool,
) -> Result<(ProvekitProof<Bn254Field>, Option<SparkQueryBatch>)> {
    crate::register();

    let params = crate::frontend::input::ordered_params_from_btreemap(&prover.abi, &input_map)?;
    let phase1 = mavros_interpreter::run_phase1(
        &prover.binary,
        prover.witness_layout,
        prover.constraints_layout,
        &params,
    )
    .context("While running Mavros witness phase 1")?;

    let num_public_inputs = prover.num_public_inputs;
    let public_inputs = if num_public_inputs == 0 {
        PublicInputs::new()
    } else {
        PublicInputs::from_vec(phase1.out_wit_pre_comm[1..=num_public_inputs].to_vec())
    };

    // Set up transcript with public inputs bound to the instance.
    let instance = public_inputs.hash_bytes::<Bn254Field>(prover.hash_config);
    let ds = prover
        .whir_for_witness
        .create_domain_separator()
        .instance(&instance);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(prover.hash_config));

    info!(
        ?prover.witness_layout,
        ?prover.constraints_layout,
        scheme_domain_len = prover.whir_for_witness.domain_size(),
        "Mavros witness layout"
    );

    let w1 = phase1.out_wit_pre_comm.clone();
    log_commit_input(
        "mavros_w1_pre_commitment",
        &w1,
        prover.whir_for_witness.domain_size(),
    );
    let commitment_1 = prover
        .whir_for_witness
        .commit(
            &mut merlin,
            prover.witness_layout.size(),
            prover.constraints_layout.algebraic_size,
            w1,
            true,
        )
        .context("While committing to w1")?;

    let (commitments, witgen_result) = if prover.whir_for_witness.num_challenges > 0 {
        let challenges: Vec<FieldElement> = (0..prover.witness_layout.challenges_size)
            .map(|_| merlin.verifier_message())
            .collect();

        let witgen_result = mavros_interpreter::run_phase2(
            phase1,
            &challenges,
            prover.witness_layout,
            prover.constraints_layout,
        );

        let mut witgen_result = witgen_result;
        let w2 = take(&mut witgen_result.out_wit_post_comm);
        log_commit_input(
            "mavros_w2_post_commitment",
            &w2,
            prover.whir_for_witness.domain_size(),
        );
        let commitment_2 = prover
            .whir_for_witness
            .commit(
                &mut merlin,
                prover.witness_layout.size(),
                prover.constraints_layout.algebraic_size,
                w2,
                false,
            )
            .context("While committing to w2")?;

        (vec![commitment_1, commitment_2], witgen_result)
    } else {
        let witgen_result = mavros_interpreter::run_phase2(
            phase1,
            &[],
            prover.witness_layout,
            prover.constraints_layout,
        );
        (vec![commitment_1], witgen_result)
    };

    let (whir_r1cs_proof, r1cs_spark_queries) = if produce_spark_query {
        let (proof, queries) = prover
            .whir_for_witness
            .prove_mavros_with_spark(
                merlin,
                witgen_result,
                commitments,
                &public_inputs,
                prover.witness_layout,
                prover.constraints_layout,
                &prover.binary,
            )
            .context("While proving R1CS instance")?;
        (proof, Some(SparkQueryBatch::from(queries)))
    } else {
        let proof = prover
            .whir_for_witness
            .prove_mavros(
                merlin,
                witgen_result,
                commitments,
                &public_inputs,
                prover.witness_layout,
                prover.constraints_layout,
                &prover.binary,
            )
            .context("While proving R1CS instance")?;
        (proof, None)
    };

    Ok((
        ProvekitProof {
            public_inputs,
            whir_r1cs_proof,
        },
        r1cs_spark_queries,
    ))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "witness-generation"))]
fn mavros_input_map_from_toml(abi: &noirc_abi::Abi, prover_toml: &Path) -> Result<InputMap> {
    let project_path = prover_toml
        .parent()
        .context("Could not derive project path from Prover.toml path")?;
    crate::frontend::input::read_prover_inputs(&project_path.to_path_buf(), abi)
}

#[cfg(not(target_arch = "wasm32"))]
impl Prove for MavrosProver {
    #[cfg(feature = "witness-generation")]
    fn prove(self, input_map: InputMap) -> Result<ProvekitProof<Bn254Field>> {
        let (proof, _) = prove_mavros_inner(self, input_map, false)?;
        Ok(proof)
    }

    #[cfg(feature = "witness-generation")]
    #[instrument(skip_all)]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<ProvekitProof<Bn254Field>> {
        let input_map = mavros_input_map_from_toml(&self.abi, prover_toml.as_ref())?;
        self.prove(input_map)
    }

    fn prove_with_witness(
        self,
        _witness: WitnessMap<NoirElement>,
    ) -> Result<ProvekitProof<Bn254Field>> {
        Err(anyhow::anyhow!(
            "prove_with_witness is not supported for Mavros prover"
        ))
    }

    #[cfg(feature = "witness-generation")]
    #[instrument(skip_all)]
    fn prove_with_spark_toml(
        self,
        prover_toml: impl AsRef<Path>,
    ) -> Result<(ProvekitProof<Bn254Field>, SparkQueryBatch)> {
        let input_map = mavros_input_map_from_toml(&self.abi, prover_toml.as_ref())?;
        let (proof, batch) = prove_mavros_inner(self, input_map, true)?;
        let batch = batch
            .ok_or_else(|| anyhow::anyhow!("SPARK query batch must be produced when requested"))?;
        Ok((proof, batch))
    }
}

impl Prove for Prover {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<ProvekitProof<Bn254Field>> {
        match self {
            Prover::Noir(p) => p.prove(input_map),
            Prover::Mavros(p) => p.prove(input_map),
        }
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<ProvekitProof<Bn254Field>> {
        match self {
            Prover::Noir(p) => p.prove_with_toml(prover_toml),
            Prover::Mavros(p) => p.prove_with_toml(prover_toml),
        }
    }

    fn prove_with_witness(
        self,
        witness: WitnessMap<NoirElement>,
    ) -> Result<ProvekitProof<Bn254Field>> {
        match self {
            Prover::Noir(p) => p.prove_with_witness(witness),
            #[cfg(not(target_arch = "wasm32"))]
            Prover::Mavros(p) => p.prove_with_witness(witness),
            #[cfg(target_arch = "wasm32")]
            Prover::Mavros(_) => {
                anyhow::bail!("Mavros prover is not supported on WASM")
            }
        }
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_spark_toml(
        self,
        prover_toml: impl AsRef<Path>,
    ) -> Result<(ProvekitProof<Bn254Field>, SparkQueryBatch)> {
        match self {
            Prover::Noir(p) => p.prove_with_spark_toml(prover_toml),
            Prover::Mavros(p) => p.prove_with_spark_toml(prover_toml),
        }
    }
}
