use {
    crate::{
        Bn254Field, ConstraintsLayout, FieldElement, MavrosProver, ProvekitProof, TranscriptSponge,
        WitnessLayout,
    },
    anyhow::{Context, Result},
    provekit_common::{
        prefix_covector::expand_powers,
        utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq, PublicInputs,
        PublicInputsHash, WhirR1CSProof, WhirR1CSScheme,
    },
    provekit_prover::{
        prove_from_alphas, run_zk_sumcheck_prover, WhirR1CSCommitment, WhirR1CSProver,
    },
    tracing::instrument,
    whir::transcript::{ProverState, VerifierMessage},
};

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

struct MavrosWitgenResult {
    out_wit_post_comm: Vec<FieldElement>,
    out_a:             Vec<FieldElement>,
    out_b:             Vec<FieldElement>,
    out_c:             Vec<FieldElement>,
}

/// Generates a proof for a Mavros prover using a caller-provided WASM driver.
#[instrument(skip_all)]
pub fn prove_mavros_with_wasm_driver<D: MavrosWasmDriver>(
    prover: MavrosProver,
    input_fields: Vec<FieldElement>,
    driver: &mut D,
) -> Result<ProvekitProof<Bn254Field>> {
    crate::register();

    let mut phase1 = driver
        .run_witgen(
            &input_fields,
            prover.witness_layout,
            prover.constraints_layout,
        )
        .context("while running Mavros WASM witness generation")?;
    validate_mavros_phase1(
        &phase1,
        prover.num_public_inputs,
        prover.witness_layout,
        prover.constraints_layout,
    )?;

    let public_inputs = if prover.num_public_inputs == 0 {
        PublicInputs::new()
    } else {
        PublicInputs::from_vec(phase1.out_wit_pre_comm[1..=prover.num_public_inputs].to_vec())
    };

    let instance = public_inputs.hash_bytes::<Bn254Field>(prover.hash_config);
    let ds = prover
        .whir_for_witness
        .create_domain_separator()
        .instance(&instance);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(prover.hash_config));

    let commitment_1 = prover
        .whir_for_witness
        .commit(
            &mut merlin,
            prover.witness_layout.size(),
            prover.constraints_layout.algebraic_size,
            phase1.out_wit_pre_comm.clone(),
            true,
        )
        .context("While committing to Mavros w1")?;

    let witgen_result = if prover.whir_for_witness.num_challenges > 0 {
        let challenges: Vec<FieldElement> = (0..prover.witness_layout.challenges_size)
            .map(|_| merlin.verifier_message())
            .collect();
        run_mavros_phase2(
            &mut phase1,
            &challenges,
            prover.witness_layout,
            prover.constraints_layout,
        )
        .context("while completing Mavros phase2")?
    } else {
        run_mavros_phase2(
            &mut phase1,
            &[],
            prover.witness_layout,
            prover.constraints_layout,
        )
        .context("while completing Mavros phase2")?
    };

    let commitments = if prover.whir_for_witness.num_challenges > 0 {
        let commitment_2 = prover
            .whir_for_witness
            .commit(
                &mut merlin,
                prover.witness_layout.size(),
                prover.constraints_layout.algebraic_size,
                witgen_result.out_wit_post_comm.clone(),
                false,
            )
            .context("While committing to Mavros w2")?;
        vec![commitment_1, commitment_2]
    } else {
        vec![commitment_1]
    };

    let whir_r1cs_proof = prove_mavros_with_ad_callback(
        &prover.whir_for_witness,
        merlin,
        witgen_result,
        commitments,
        &public_inputs,
        prover.constraints_layout,
        |coeffs| {
            let alphas = driver
                .run_ad(coeffs, prover.witness_layout, prover.constraints_layout)
                .context("while running Mavros WASM AD")?;
            for (name, len) in [
                ("dA", alphas[0].len()),
                ("dB", alphas[1].len()),
                ("dC", alphas[2].len()),
            ] {
                anyhow::ensure!(
                    len == prover.witness_layout.size(),
                    "Mavros AD {name} length {len} does not match witness layout {}",
                    prover.witness_layout.size()
                );
            }
            Ok(alphas)
        },
    )
    .context("While proving Mavros R1CS instance")?;

    Ok(ProvekitProof {
        public_inputs,
        whir_r1cs_proof,
    })
}

#[instrument(skip_all)]
fn prove_mavros_with_ad_callback<F>(
    scheme: &WhirR1CSScheme<Bn254Field>,
    mut merlin: ProverState<TranscriptSponge>,
    witgen: MavrosWitgenResult,
    commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
    public_inputs: &PublicInputs<FieldElement>,
    constraints_layout: ConstraintsLayout,
    run_ad: F,
) -> Result<WhirR1CSProof>
where
    F: FnOnce(&[FieldElement]) -> Result<[Vec<FieldElement>; 3]>,
{
    anyhow::ensure!(!commitments.is_empty(), "Need at least one commitment");

    let blinding = commitments[0]
        .blinding
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("c1 must carry blinding state"))?;

    let [a, b, c] = [witgen.out_a, witgen.out_b, witgen.out_c];
    let (alpha, blinding_eval) = run_zk_sumcheck_prover(
        a,
        b,
        c,
        &mut merlin,
        scheme.m_0,
        &blinding.polynomial,
        &commitments[0].polynomial,
        blinding.offset,
    );

    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha, 1 << alpha.len());
    let alphas = run_ad(&eq_alpha[..constraints_layout.size()])?;

    prove_from_alphas(
        scheme,
        merlin,
        alphas,
        blinding_eval,
        blinding.offset,
        expand_powers::<4, _>(&alpha),
        commitments,
        public_inputs,
    )
}

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

fn checked_end(start: usize, len: usize, label: &str) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("Mavros {label} range overflow"))
}

fn ensure_range(end: usize, bound: usize, label: &str) -> Result<()> {
    anyhow::ensure!(
        end <= bound,
        "Mavros {label} range ends at {end}, past buffer length {bound}"
    );
    Ok(())
}

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
