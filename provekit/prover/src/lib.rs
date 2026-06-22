#[cfg(test)]
use crate::r1cs::R1CSSolver;
#[cfg(target_arch = "wasm32")]
use {
    crate::whir_r1cs::MavrosWitgenResult,
    provekit_common::{ConstraintsLayout, MavrosProver, WitnessLayout},
    whir::transcript::VerifierMessage,
};
use {
    crate::{
        r1cs::{CompressedLayers, CompressedR1CS},
        whir_r1cs::WhirR1CSProver,
    },
    ::tracing::{debug, info_span, instrument},
    acir::native_types::{Witness, WitnessMap},
    anyhow::{Context, Result},
    provekit_common::{
        utils::noir_to_native, FieldElement, NoirElement, NoirProof, NoirProver, Prover,
        PublicInputs, TranscriptSponge,
    },
    std::mem::size_of,
    whir::transcript::ProverState,
};
#[cfg(not(target_arch = "wasm32"))]
use {
    ::tracing::info, mavros_vm::interpreter as mavros_interpreter, provekit_common::MavrosProver,
    std::mem::take, std::path::Path, whir::transcript::VerifierMessage,
};
#[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
use {
    bn254_blackbox_solver::Bn254BlackBoxSolver, nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file, noirc_abi::InputMap,
};

pub(crate) mod bigint_mod;
pub(crate) mod ec_arith;
#[cfg(not(target_arch = "wasm32"))]
pub mod input_utils;
mod logging;
pub(crate) mod r1cs;
mod whir_r1cs;
mod witness;

// Public re-exports for items used by integration tests and benchmarks.
pub use {ec_arith::ec_scalar_mul, r1cs::solve_witness_vec};

#[cfg(target_arch = "wasm32")]
/// Table metadata returned by a browser-side Mavros witness generator.
#[derive(Clone, Debug)]
pub struct MavrosTableInfo {
    /// Offset of this table's multiplicity slots in the pre-commitment witness.
    pub multiplicities_wit_offset: usize,
    /// Number of values carried by each lookup key beyond the index column.
    pub num_values: usize,
    /// Number of rows in the table.
    pub length: usize,
    /// Offset of element inverse witnesses in the post-commitment witness.
    pub elem_inverses_witness_section_offset: usize,
    /// Offset of element inverse constraints in the A/B/C vectors.
    pub elem_inverses_constraint_section_offset: usize,
}

/// Phase-1 output produced by a browser-side Mavros witness generator.
#[cfg(target_arch = "wasm32")]
pub struct MavrosPhase1Result {
    /// Witness values committed before Fiat-Shamir challenges are sampled.
    pub out_wit_pre_comm:  Vec<FieldElement>,
    /// Witness slots filled after Fiat-Shamir challenges are sampled.
    pub out_wit_post_comm: Vec<FieldElement>,
    /// Constraint matrix A values emitted by Mavros.
    pub out_a:             Vec<FieldElement>,
    /// Constraint matrix B values emitted by Mavros.
    pub out_b:             Vec<FieldElement>,
    /// Constraint matrix C values emitted by Mavros.
    pub out_c:             Vec<FieldElement>,
    /// Lookup table metadata needed to complete phase 2.
    pub tables:            Vec<MavrosTableInfo>,
}

/// Driver implemented by the WASM bindings to execute browser-side Mavros
/// modules.
#[cfg(target_arch = "wasm32")]
pub trait MavrosWasmDriver {
    /// Runs Mavros witness generation and returns phase-1 buffers.
    fn run_witgen(
        &mut self,
        input_fields: &[FieldElement],
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
    ) -> Result<MavrosPhase1Result>;

    /// Runs Mavros automatic differentiation for the supplied coefficients.
    fn run_ad(
        &mut self,
        coeffs: &[FieldElement],
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
    ) -> Result<[Vec<FieldElement>; 3]>;
}

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

        crate::logging::log_commit_input("noir_w1", &w1, self.whir_for_witness.domain_size());
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

            crate::logging::log_commit_input("noir_w2", &w2, self.whir_for_witness.domain_size());
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

        Ok(NoirProof {
            public_inputs,
            whir_r1cs_proof,
        })
    }
}

/// Generates a proof for a Mavros prover using a caller-provided WASM driver.
#[cfg(target_arch = "wasm32")]
#[instrument(skip_all)]
pub fn prove_mavros_with_wasm_driver<D: MavrosWasmDriver>(
    prover: MavrosProver,
    input_fields: Vec<FieldElement>,
    driver: &mut D,
) -> Result<NoirProof> {
    let self_ = prover;
    provekit_common::register_ntt();

    let mut phase1 = driver
        .run_witgen(
            &input_fields,
            self_.witness_layout,
            self_.constraints_layout,
        )
        .context("while running Mavros WASM witness generation")?;
    validate_mavros_phase1(
        &phase1,
        self_.num_public_inputs,
        self_.witness_layout,
        self_.constraints_layout,
    )?;

    let num_public_inputs = self_.num_public_inputs;
    let public_inputs = if num_public_inputs == 0 {
        PublicInputs::new()
    } else {
        PublicInputs::from_vec(phase1.out_wit_pre_comm[1..=num_public_inputs].to_vec())
    };

    let instance = public_inputs.hash_bytes(self_.hash_config);
    let ds = self_
        .whir_for_witness
        .create_domain_separator()
        .instance(&instance);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(self_.hash_config));

    let commitment_1 = self_
        .whir_for_witness
        .commit(
            &mut merlin,
            self_.witness_layout.size(),
            self_.constraints_layout.algebraic_size,
            phase1.out_wit_pre_comm.clone(),
            true,
        )
        .context("While committing to Mavros w1")?;

    let witgen_result = if self_.whir_for_witness.num_challenges > 0 {
        let challenges: Vec<FieldElement> = (0..self_.witness_layout.challenges_size)
            .map(|_| merlin.verifier_message())
            .collect();
        run_mavros_phase2(
            &mut phase1,
            &challenges,
            self_.witness_layout,
            self_.constraints_layout,
        )
        .context("while completing Mavros phase2")?
    } else {
        run_mavros_phase2(
            &mut phase1,
            &[],
            self_.witness_layout,
            self_.constraints_layout,
        )
        .context("while completing Mavros phase2")?
    };

    let commitments = if self_.whir_for_witness.num_challenges > 0 {
        let commitment_2 = self_
            .whir_for_witness
            .commit(
                &mut merlin,
                self_.witness_layout.size(),
                self_.constraints_layout.algebraic_size,
                witgen_result.out_wit_post_comm.clone(),
                false,
            )
            .context("While committing to Mavros w2")?;
        vec![commitment_1, commitment_2]
    } else {
        vec![commitment_1]
    };

    let whir_r1cs_proof = self_
        .whir_for_witness
        .prove_mavros_with_ad_callback(
            merlin,
            witgen_result,
            commitments,
            &public_inputs,
            self_.constraints_layout,
            |coeffs| {
                let alphas = driver
                    .run_ad(coeffs, self_.witness_layout, self_.constraints_layout)
                    .context("while running Mavros WASM AD")?;
                for (name, len) in [
                    ("dA", alphas[0].len()),
                    ("dB", alphas[1].len()),
                    ("dC", alphas[2].len()),
                ] {
                    anyhow::ensure!(
                        len == self_.witness_layout.size(),
                        "Mavros AD {name} length {len} does not match witness layout {}",
                        self_.witness_layout.size()
                    );
                }
                Ok(alphas)
            },
        )
        .context("While proving Mavros R1CS instance")?;

    Ok(NoirProof {
        public_inputs,
        whir_r1cs_proof,
    })
}

#[cfg(target_arch = "wasm32")]
fn validate_mavros_phase1(
    phase1: &MavrosPhase1Result,
    num_public_inputs: usize,
    witness_layout: WitnessLayout,
    constraints_layout: ConstraintsLayout,
) -> Result<()> {
    anyhow::ensure!(
        phase1.out_wit_pre_comm.len() == witness_layout.pre_commitment_size(),
        "Mavros pre-commitment witness length {} does not match layout {}",
        phase1.out_wit_pre_comm.len(),
        witness_layout.pre_commitment_size()
    );
    anyhow::ensure!(
        phase1.out_wit_post_comm.len() == witness_layout.post_commitment_size(),
        "Mavros post-commitment witness length {} does not match layout {}",
        phase1.out_wit_post_comm.len(),
        witness_layout.post_commitment_size()
    );
    anyhow::ensure!(
        num_public_inputs < phase1.out_wit_pre_comm.len(),
        "Mavros pre-commitment witness does not contain {num_public_inputs} public inputs plus \
         constant slot"
    );
    for (name, len) in [
        ("A", phase1.out_a.len()),
        ("B", phase1.out_b.len()),
        ("C", phase1.out_c.len()),
    ] {
        anyhow::ensure!(
            len == constraints_layout.size(),
            "Mavros {name} length {len} does not match constraints layout {}",
            constraints_layout.size()
        );
    }

    for (index, table) in phase1.tables.iter().enumerate() {
        validate_mavros_table(index, table, phase1, witness_layout, constraints_layout)?;
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn checked_end(start: usize, len: usize, label: &str) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("Mavros {label} range overflow"))
}

#[cfg(target_arch = "wasm32")]
fn ensure_range(end: usize, bound: usize, label: &str) -> Result<()> {
    anyhow::ensure!(
        end <= bound,
        "Mavros {label} range ends at {end}, past buffer length {bound}"
    );
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn validate_mavros_table(
    index: usize,
    table: &MavrosTableInfo,
    phase1: &MavrosPhase1Result,
    witness_layout: WitnessLayout,
    constraints_layout: ConstraintsLayout,
) -> Result<()> {
    anyhow::ensure!(
        table.num_values <= 1,
        "Mavros table {index} has unsupported num_values={}",
        table.num_values
    );
    anyhow::ensure!(
        phase1.out_wit_post_comm.len() > table.num_values,
        "Mavros table {index} requires {} Fiat-Shamir challenge slots, but post-commitment \
         witness has {}",
        table.num_values + 1,
        phase1.out_wit_post_comm.len()
    );

    let multiplicities_end = checked_end(
        table.multiplicities_wit_offset,
        table.length,
        "multiplicity",
    )?;
    ensure_range(
        multiplicities_end,
        phase1.out_wit_pre_comm.len(),
        "multiplicity",
    )?;

    let inverse_constraint_len = if table.num_values == 0 {
        table.length.checked_add(1)
    } else {
        table
            .length
            .checked_mul(2)
            .and_then(|len| len.checked_add(1))
    }
    .ok_or_else(|| anyhow::anyhow!("Mavros table {index} inverse constraint range overflow"))?;
    let inverse_constraint_end = checked_end(
        table.elem_inverses_constraint_section_offset,
        inverse_constraint_len,
        "inverse constraint",
    )?;
    ensure_range(inverse_constraint_end, phase1.out_a.len(), "inverse A")?;
    ensure_range(inverse_constraint_end, phase1.out_b.len(), "inverse B")?;
    ensure_range(inverse_constraint_end, phase1.out_c.len(), "inverse C")?;
    ensure_range(
        inverse_constraint_end,
        constraints_layout.size(),
        "inverse constraint layout",
    )?;

    let inverse_witness_len = if table.num_values == 0 {
        table.length
    } else {
        table
            .length
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("Mavros table {index} inverse witness range overflow"))?
    };
    let inverse_witness_end = checked_end(
        table.elem_inverses_witness_section_offset,
        inverse_witness_len,
        "inverse witness",
    )?;
    ensure_range(
        inverse_witness_end,
        phase1.out_wit_post_comm.len(),
        "inverse witness",
    )?;
    ensure_range(
        inverse_witness_end,
        witness_layout.post_commitment_size(),
        "inverse witness layout",
    )?;

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn run_mavros_phase2(
    phase1: &mut MavrosPhase1Result,
    challenges: &[FieldElement],
    witness_layout: WitnessLayout,
    constraints_layout: ConstraintsLayout,
) -> Result<MavrosWitgenResult> {
    use {
        ark_ff::Field,
        ark_std::{One, Zero},
    };

    anyhow::ensure!(
        challenges.len() == witness_layout.challenges_size,
        "Mavros challenge count {} does not match witness layout {}",
        challenges.len(),
        witness_layout.challenges_size
    );

    for (i, challenge) in challenges.iter().enumerate() {
        phase1.out_wit_post_comm[i] = *challenge;
    }

    let mut running_prod = FieldElement::one();
    for tbl in &phase1.tables {
        let alpha = phase1.out_wit_post_comm[0];
        let base = tbl.elem_inverses_constraint_section_offset;

        if tbl.num_values == 0 {
            for i in 0..tbl.length {
                let multiplicity = phase1.out_wit_pre_comm[tbl.multiplicities_wit_offset + i];
                let denom = alpha - FieldElement::from(i as u64);
                phase1.out_b[base + i] = denom;
                phase1.out_c[base + i] = multiplicity;
                if !multiplicity.is_zero() {
                    phase1.out_a[base + i] = running_prod;
                    running_prod *= denom;
                }
            }
        } else {
            anyhow::ensure!(
                tbl.num_values == 1,
                "expected width-2 table, got num_values={}",
                tbl.num_values
            );
            let beta = phase1.out_wit_post_comm[1];
            for i in 0..tbl.length {
                let multiplicity = phase1.out_wit_pre_comm[tbl.multiplicities_wit_offset + i];
                let v_i = phase1.out_a[base + 2 * i];
                let x_i = -beta * v_i;
                phase1.out_a[base + 2 * i] = beta;
                phase1.out_b[base + 2 * i] = v_i;
                phase1.out_c[base + 2 * i] = -x_i;

                let denom = alpha - FieldElement::from(i as u64) - x_i;
                phase1.out_b[base + 2 * i + 1] = denom;
                phase1.out_c[base + 2 * i + 1] = multiplicity;
                if !multiplicity.is_zero() {
                    phase1.out_a[base + 2 * i + 1] = running_prod;
                    running_prod *= denom;
                }
            }
        }
    }

    let mut running_inv = running_prod
        .inverse()
        .ok_or_else(|| anyhow::anyhow!("Mavros lookup running product is not invertible"))?;

    for tbl in phase1.tables.iter().rev() {
        let base = tbl.elem_inverses_constraint_section_offset;

        if tbl.num_values == 0 {
            for i in (0..tbl.length).rev() {
                let multiplicity = phase1.out_c[base + i];
                let denom = phase1.out_b[base + i];
                let running_prod = phase1.out_a[base + i];
                if !multiplicity.is_zero() {
                    let elem = running_prod * running_inv;
                    phase1.out_a[base + i] = elem;
                    running_inv *= denom;
                }
            }
        } else {
            for i in (0..tbl.length).rev() {
                let multiplicity = phase1.out_c[base + 2 * i + 1];
                let denom = phase1.out_b[base + 2 * i + 1];
                let running_prod = phase1.out_a[base + 2 * i + 1];
                if !multiplicity.is_zero() {
                    let elem = running_prod * running_inv;
                    phase1.out_a[base + 2 * i + 1] = elem;
                    running_inv *= denom;
                }
            }
        }
    }

    let mut current_lookup_off = 0;
    while current_lookup_off < constraints_layout.lookups_data_size {
        let cnst_off = constraints_layout.lookups_data_start() + current_lookup_off;
        let wit_off = witness_layout.lookups_data_start() - witness_layout.challenges_start()
            + current_lookup_off;
        anyhow::ensure!(
            cnst_off < phase1.out_a.len() && wit_off < phase1.out_wit_post_comm.len(),
            "Mavros lookup offset out of bounds: constraint {cnst_off}, witness {wit_off}"
        );
        let table_ix = phase1.out_a[cnst_off].0 .0[0] as usize;
        let table = phase1.tables.get(table_ix).ok_or_else(|| {
            anyhow::anyhow!(
                "Mavros lookup references table {table_ix}, but only {} tables exist",
                phase1.tables.len()
            )
        })?;
        let alpha = phase1.out_wit_post_comm[0];

        if table.num_values == 0 {
            let flag_u64 = phase1.out_c[cnst_off].0 .0[0];
            if flag_u64 == 0 {
                let key = phase1.out_b[cnst_off];
                phase1.out_a[cnst_off] = FieldElement::zero();
                phase1.out_b[cnst_off] = alpha - key;
                phase1.out_c[cnst_off] = FieldElement::zero();
                phase1.out_wit_post_comm[wit_off] = FieldElement::zero();
            } else {
                let ix_in_table = phase1.out_b[cnst_off].0 .0[0] as usize;
                anyhow::ensure!(
                    ix_in_table < table.length,
                    "Mavros lookup index {ix_in_table} is out of bounds for table {table_ix} \
                     length {}",
                    table.length
                );
                let src = table.elem_inverses_constraint_section_offset + ix_in_table;
                phase1.out_a[cnst_off] = phase1.out_a[src];
                phase1.out_b[cnst_off] = phase1.out_b[src];
                phase1.out_c[cnst_off] = FieldElement::from(flag_u64);
                phase1.out_wit_post_comm[wit_off] = phase1.out_a[cnst_off];
                let sum = table.elem_inverses_constraint_section_offset + table.length;
                phase1.out_c[sum] += phase1.out_a[cnst_off];
            }
            current_lookup_off += 1;
        } else {
            anyhow::ensure!(
                cnst_off + 1 < phase1.out_a.len() && wit_off + 1 < phase1.out_wit_post_comm.len(),
                "Mavros width-2 lookup offset out of bounds: constraint {}, witness {}",
                cnst_off + 1,
                wit_off + 1
            );
            let beta = phase1.out_wit_post_comm[1];
            let result_value = phase1.out_b[cnst_off];
            let flag_u64 = phase1.out_c[cnst_off + 1].0 .0[0];
            let x = -beta * result_value;
            phase1.out_a[cnst_off] = beta;
            phase1.out_b[cnst_off] = result_value;
            phase1.out_c[cnst_off] = -x;
            phase1.out_wit_post_comm[wit_off] = x;

            let y_cnst_off = cnst_off + 1;
            let y_wit_off = wit_off + 1;
            if flag_u64 == 0 {
                let key = phase1.out_b[y_cnst_off];
                phase1.out_a[y_cnst_off] = FieldElement::zero();
                phase1.out_b[y_cnst_off] = alpha - key - x;
                phase1.out_c[y_cnst_off] = FieldElement::zero();
                phase1.out_wit_post_comm[y_wit_off] = FieldElement::zero();
            } else {
                let ix_in_table = phase1.out_b[y_cnst_off].0 .0[0] as usize;
                anyhow::ensure!(
                    ix_in_table < table.length,
                    "Mavros lookup index {ix_in_table} is out of bounds for table {table_ix} \
                     length {}",
                    table.length
                );
                let src = table.elem_inverses_constraint_section_offset + 2 * ix_in_table + 1;
                phase1.out_a[y_cnst_off] = phase1.out_a[src];
                phase1.out_b[y_cnst_off] = phase1.out_b[src];
                phase1.out_c[y_cnst_off] = FieldElement::from(flag_u64);
                phase1.out_wit_post_comm[y_wit_off] = phase1.out_a[y_cnst_off];
                let sum = table.elem_inverses_constraint_section_offset + 2 * table.length;
                phase1.out_c[sum] += phase1.out_a[y_cnst_off];
            }
            current_lookup_off += 2;
        }
    }

    for tbl in &phase1.tables {
        let base = tbl.elem_inverses_constraint_section_offset;
        let wit_base = tbl.elem_inverses_witness_section_offset;

        if tbl.num_values == 0 {
            for i in 0..tbl.length {
                let multiplicity = phase1.out_c[base + i];
                if !multiplicity.is_zero() {
                    let elem = phase1.out_a[base + i] * multiplicity;
                    phase1.out_a[base + i] = elem;
                    phase1.out_wit_post_comm[wit_base + i] = elem;
                    phase1.out_a[base + tbl.length] += elem;
                }
            }
            phase1.out_b[base + tbl.length] = FieldElement::one();
        } else {
            for i in 0..tbl.length {
                let multiplicity = phase1.out_c[base + 2 * i + 1];
                if !multiplicity.is_zero() {
                    let elem = phase1.out_a[base + 2 * i + 1] * multiplicity;
                    phase1.out_a[base + 2 * i + 1] = elem;
                    phase1.out_wit_post_comm[wit_base + 2 * i + 1] = elem;
                    phase1.out_a[base + 2 * tbl.length] += elem;
                }
                phase1.out_wit_post_comm[wit_base + 2 * i] = -phase1.out_c[base + 2 * i];
            }
            phase1.out_b[base + 2 * tbl.length] = FieldElement::one();
        }
    }

    Ok(MavrosWitgenResult {
        out_wit_post_comm: std::mem::take(&mut phase1.out_wit_post_comm),
        out_a:             std::mem::take(&mut phase1.out_a),
        out_b:             std::mem::take(&mut phase1.out_b),
        out_c:             std::mem::take(&mut phase1.out_c),
    })
}

#[cfg(not(target_arch = "wasm32"))]
impl Prove for MavrosProver {
    #[cfg(feature = "witness-generation")]
    fn prove(self, input_map: InputMap) -> Result<NoirProof> {
        provekit_common::register_ntt();

        let params = crate::input_utils::ordered_params_from_btreemap(&self.abi, &input_map)?;
        let phase1 = mavros_interpreter::run_phase1(
            &self.binary,
            self.witness_layout,
            self.constraints_layout,
            &params,
        )
        .context("While running Mavros witness phase 1")?;

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

        info!(
            ?self.witness_layout,
            ?self.constraints_layout,
            scheme_domain_len = self.whir_for_witness.domain_size(),
            "Mavros witness layout"
        );

        let w1 = phase1.out_wit_pre_comm.clone();
        crate::logging::log_commit_input(
            "mavros_w1_pre_commitment",
            &w1,
            self.whir_for_witness.domain_size(),
        );
        let commitment_1 = self
            .whir_for_witness
            .commit(
                &mut merlin,
                self.witness_layout.size(),
                self.constraints_layout.algebraic_size,
                w1,
                true,
            )
            .context("While committing to w1")?;

        let (commitments, witgen_result) = if self.whir_for_witness.num_challenges > 0 {
            let challenges: Vec<FieldElement> = (0..self.witness_layout.challenges_size)
                .map(|_| merlin.verifier_message())
                .collect();

            let witgen_result = mavros_interpreter::run_phase2(
                phase1,
                &challenges,
                self.witness_layout,
                self.constraints_layout,
            );

            let mut witgen_result = witgen_result;
            let w2 = take(&mut witgen_result.out_wit_post_comm);
            crate::logging::log_commit_input(
                "mavros_w2_post_commitment",
                &w2,
                self.whir_for_witness.domain_size(),
            );
            let commitment_2 = self
                .whir_for_witness
                .commit(
                    &mut merlin,
                    self.witness_layout.size(),
                    self.constraints_layout.algebraic_size,
                    w2,
                    false,
                )
                .context("While committing to w2")?;

            (vec![commitment_1, commitment_2], witgen_result)
        } else {
            let witgen_result = mavros_interpreter::run_phase2(
                phase1,
                &[],
                self.witness_layout,
                self.constraints_layout,
            );
            (vec![commitment_1], witgen_result)
        };

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove_mavros(
                merlin,
                witgen_result,
                commitments,
                &public_inputs,
                self.witness_layout,
                self.constraints_layout,
                &self.binary,
            )
            .context("While proving R1CS instance")?;

        Ok(NoirProof {
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

impl Prove for Prover {
    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove(self, input_map: InputMap) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove(input_map),
            Prover::Mavros(p) => p.prove(input_map),
        }
    }

    #[cfg(all(feature = "witness-generation", not(target_arch = "wasm32")))]
    fn prove_with_toml(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        match self {
            Prover::Noir(p) => p.prove_with_toml(prover_toml),
            Prover::Mavros(p) => p.prove_with_toml(prover_toml),
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
        }
    }
}
