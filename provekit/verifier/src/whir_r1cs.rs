use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        prefix_covector::{build_prefix_covectors, expand_powers, make_public_weight},
        utils::sumcheck::{
            calculate_eq, eval_cubic_poly, multiply_transposed_by_eq_alpha, transpose_r1cs_matrices,
        },
        FieldElement, PrefixCovector, PublicInputs, TranscriptSponge, WhirR1CSProof,
        WhirR1CSScheme, WhirZkConfig, R1CS,
    },
    tracing::instrument,
    whir::{
        algebra::linear_form::LinearForm,
        transcript::{codecs::Empty, Proof, VerifierMessage, VerifierState},
    },
};

pub struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

pub trait WhirR1CSVerifier {
    fn verify(&self, proof: WhirR1CSProof, public_inputs: &PublicInputs, r1cs: &R1CS)
        -> Result<()>;
}

impl WhirR1CSVerifier for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn verify(
        &self,
        proof: WhirR1CSProof,
        public_inputs: &PublicInputs,
        r1cs: &R1CS,
    ) -> Result<()> {
        let ds = self.create_domain_separator().instance(&Empty);
        let whir_proof = Proof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        };
        let mut arthur = VerifierState::new(&ds, &whir_proof, TranscriptSponge::default());

        // Receive first commitment (always present)
        let commitment_1 = self
            .whir_witness
            .receive_commitments(&mut arthur, 1)
            .map_err(|_| anyhow::anyhow!("Failed to parse commitment 1"))?;

        // Parse second commitment only if we have challenges (dual commit)
        let commitment_2 = if self.num_challenges > 0 {
            let _logup_challenges: Vec<FieldElement> =
                arthur.verifier_message_vec(self.num_challenges);
            Some(
                self.whir_witness
                    .receive_commitments(&mut arthur, 1)
                    .map_err(|_| anyhow::anyhow!("Failed to parse commitment 2"))?,
            )
        } else {
            None
        };

        // Overlap: transpose R1CS matrices while running sumcheck verification.
        // Transpose depends only on the R1CS structure, not on proof data.
        let (transposed, sumcheck_result) = rayon::join(
            || transpose_r1cs_matrices(r1cs),
            || run_sumcheck_verifier(&mut arthur, self.m_0, &self.whir_for_hiding_spartan),
        );
        let data_from_sumcheck_verifier = sumcheck_result.context("while verifying sumcheck")?;
        let (at, bt, ct) = transposed;

        let public_inputs_hash_buf: FieldElement = arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("Failed to read public inputs hash"))?;
        let expected_public_inputs_hash = public_inputs.hash();
        ensure!(
            public_inputs_hash_buf == expected_public_inputs_hash,
            "Public inputs hash mismatch: expected {:?}, got {:?}",
            expected_public_inputs_hash,
            public_inputs_hash_buf
        );
        let x: FieldElement = arthur.verifier_message();

        let alphas = multiply_transposed_by_eq_alpha(
            &at,
            &bt,
            &ct,
            &data_from_sumcheck_verifier.alpha,
            r1cs,
        );

        let (az_at_alpha, bz_at_alpha, cz_at_alpha) = if let Some(commitment_2) = commitment_2 {
            let (alphas_1, alphas_2): (Vec<_>, Vec<_>) = alphas
                .into_iter()
                .map(|mut v| {
                    let v2 = v.split_off(self.w1_size);
                    (v, v2)
                })
                .unzip();
            let alphas_1: [Vec<FieldElement>; 3] = alphas_1
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 3 alpha vectors for commitment 1"))?;
            let alphas_2: [Vec<FieldElement>; 3] = alphas_2
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 3 alpha vectors for commitment 2"))?;

            // Read evaluation hints
            let evals_1: Vec<FieldElement> = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read evals_1 hint"))?;
            let evals_2: Vec<FieldElement> = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read evals_2 hint"))?;
            let evals_1: [FieldElement; 3] = evals_1
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 3 evaluation values for commitment 1"))?;
            let evals_2: [FieldElement; 3] = evals_2
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 3 evaluation values for commitment 2"))?;

            // Read public weight hints
            let public_1: FieldElement = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read public_1 hint"))?;
            let public_2: FieldElement = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read public_2 hint"))?;

            // Build non-deferred weights for c1 from alphas_1
            let mut weights_1 = build_prefix_covectors(self.m, alphas_1);
            let mut weights_2 = build_prefix_covectors(self.m, alphas_2);

            // Insert public weight at front if needed
            if !public_inputs.is_empty() {
                weights_1.insert(0, make_public_weight(x, public_inputs.len(), self.m));
                weights_2.insert(0, make_public_weight(x, public_inputs.len(), self.m));
            }

            // Build evaluations for c1: [public_1, evals_1[0], evals_1[1], evals_1[2]]
            let evaluations_1 = if !public_inputs.is_empty() {
                vec![public_1, evals_1[0], evals_1[1], evals_1[2]]
            } else {
                evals_1.to_vec()
            };
            let evaluations_2 = if !public_inputs.is_empty() {
                vec![public_2, evals_2[0], evals_2[1], evals_2[2]]
            } else {
                evals_2.to_vec()
            };

            // Verify c1
            let weight_refs_1: Vec<&dyn LinearForm<FieldElement>> = weights_1
                .iter()
                .map(|w| w as &dyn LinearForm<FieldElement>)
                .collect();
            self.whir_witness
                .verify(&mut arthur, &weight_refs_1, &evaluations_1, &commitment_1)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed for c1"))?;

            // Verify c2
            let weight_refs_2: Vec<&dyn LinearForm<FieldElement>> = weights_2
                .iter()
                .map(|w| w as &dyn LinearForm<FieldElement>)
                .collect();
            self.whir_witness
                .verify(&mut arthur, &weight_refs_2, &evaluations_2, &commitment_2)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed for c2"))?;

            (
                evals_1[0] + evals_2[0],
                evals_1[1] + evals_2[1],
                evals_1[2] + evals_2[2],
            )
        } else {
            // Single commitment mode
            let evals: Vec<FieldElement> = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read evals hint"))?;
            let evals: [FieldElement; 3] = evals
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected 3 evaluation values"))?;

            let public_eval: FieldElement = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read public eval hint"))?;

            // Build non-deferred weights from reconstructed alpha vectors
            let mut weights = build_prefix_covectors(self.m, alphas);

            // Insert public weight at front if needed
            if !public_inputs.is_empty() {
                weights.insert(0, make_public_weight(x, public_inputs.len(), self.m));
            }

            // Build evaluations
            let evaluations = if !public_inputs.is_empty() {
                vec![public_eval, evals[0], evals[1], evals[2]]
            } else {
                evals.to_vec()
            };

            let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
                .iter()
                .map(|w| w as &dyn LinearForm<FieldElement>)
                .collect();

            self.whir_witness
                .verify(&mut arthur, &weight_refs, &evaluations, &commitment_1)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed"))?;

            (evals[0], evals[1], evals[2])
        };

        // Check the Spartan sumcheck relation
        ensure!(
            data_from_sumcheck_verifier.last_sumcheck_val
                == (az_at_alpha * bz_at_alpha - cz_at_alpha)
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        Ok(())
    }
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    m_0: usize,
    whir_for_spartan_blinding_config: &WhirZkConfig,
) -> Result<DataFromSumcheckVerifier> {
    let r: Vec<FieldElement> = arthur.verifier_message_vec(m_0);

    // zkWHIR 2.0: receive blinding commitment
    let blinding_commitment = whir_for_spartan_blinding_config
        .receive_commitments(arthur, 1)
        .map_err(|_| anyhow::anyhow!("Failed to parse spartan blinding commitment"))?;

    let sum_g: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("Failed to read sum_g"))?;

    let rho: FieldElement = arthur.verifier_message();

    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g;

    let mut alpha = vec![FieldElement::zero(); m_0];

    for item in alpha.iter_mut().take(m_0) {
        let hhat_i: [FieldElement; 4] = [
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read hhat coeff"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read hhat coeff"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read hhat coeff"))?,
            arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("Failed to read hhat coeff"))?,
        ];
        let alpha_i: FieldElement = arthur.verifier_message();
        *item = alpha_i;
        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i);
    }

    // Read blinding polynomial evaluation hint (single value, not a pair).
    let blinding_eval: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("Failed to read blinding eval"))?;

    // Build the spartan blinding weight (expand_powers of alpha)
    let spartan_num_vars = whir_for_spartan_blinding_config.num_witness_variables();
    let weight_domain_size = 1usize << spartan_num_vars;
    let mut weight_vec = expand_powers(&alpha);
    if weight_vec.len() < weight_domain_size {
        weight_vec.resize(weight_domain_size, FieldElement::zero());
    }
    let blinding_weight = PrefixCovector::new(weight_vec, weight_domain_size);

    let blinding_weight_refs: Vec<&dyn LinearForm<FieldElement>> =
        vec![&blinding_weight as &dyn LinearForm<FieldElement>];

    // zkWHIR 2.0: verify the blinding polynomial commitment
    whir_for_spartan_blinding_config
        .verify(
            arthur,
            &blinding_weight_refs,
            &[blinding_eval],
            &blinding_commitment,
        )
        .map_err(|_| anyhow::anyhow!("WHIR blinding verification failed"))?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * blinding_eval;

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        last_sumcheck_val: f_at_alpha,
    })
}
