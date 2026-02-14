use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::sumcheck::{
            calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_cubic_poly,
        },
        FieldElement, PublicInputs, WhirConfig, WhirR1CSProof, WhirR1CSScheme, R1CS,
    },
    tracing::instrument,
    whir::{
        algebra::{
            polynomials::MultilinearPoint,
            weights::{Covector, Weights},
        },
        protocols::whir::Commitment,
        transcript::{codecs::Empty, Proof, VerifierMessage, VerifierState},
    },
};

pub struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

pub trait WhirR1CSVerifier {
    fn verify(
        &self,
        proof: &WhirR1CSProof,
        public_inputs: &PublicInputs,
        r1cs: &R1CS,
    ) -> Result<()>;
}

impl WhirR1CSVerifier for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn verify(
        &self,
        proof: &WhirR1CSProof,
        public_inputs: &PublicInputs,
        r1cs: &R1CS,
    ) -> Result<()> {
        let ds = self.create_domain_separator().instance(&Empty);
        let whir_proof = Proof {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: proof.pattern.clone(),
        };
        let mut arthur = VerifierState::new(&ds, &whir_proof, SkyscraperSponge::default());

        let commitment_1 = self
            .whir_witness
            .receive_commitment(&mut arthur)
            .map_err(|_| anyhow::anyhow!("Failed to parse commitment 1"))?;

        // Parse second commitment only if we have challenges
        let commitment_2 = if self.num_challenges > 0 {
            let _logup_challenges: Vec<FieldElement> =
                arthur.verifier_message_vec(self.num_challenges);
            Some(
                self.whir_witness
                    .receive_commitment(&mut arthur)
                    .map_err(|_| anyhow::anyhow!("Failed to parse commitment 2"))?,
            )
        } else {
            None
        };

        // Sumcheck verification (common to both paths)
        let data_from_sumcheck_verifier =
            run_sumcheck_verifier(&mut arthur, self.m_0, &self.whir_for_hiding_spartan)
                .context("while verifying sumcheck")?;

        // Verify public inputs hash
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
        let public_weights_vector_random: FieldElement = arthur.verifier_message();

        // Read hints and verify WHIR proof
        let (
            az_at_alpha,
            bz_at_alpha,
            cz_at_alpha,
            whir_folding_randomness,
            deferred_evals,
            _public_weights_challenge,
        ) = if let Some(commitment_2) = commitment_2 {
            // Dual commitment mode: read same-commitment and cross-evaluation hints
            let sums_1: (Vec<FieldElement>, Vec<FieldElement>) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read sums_1 hint"))?;
            let sums_2: (Vec<FieldElement>, Vec<FieldElement>) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read sums_2 hint"))?;
            let cross_12: (Vec<FieldElement>, Vec<FieldElement>) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read cross_12 hint"))?;
            let cross_21: (Vec<FieldElement>, Vec<FieldElement>) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read cross_21 hint"))?;

            let f_sums_1: [FieldElement; 3] = sums_1.0.try_into().unwrap();
            let g_sums_1: [FieldElement; 3] = sums_1.1.try_into().unwrap();
            let f_sums_2: [FieldElement; 3] = sums_2.0.try_into().unwrap();
            let g_sums_2: [FieldElement; 3] = sums_2.1.try_into().unwrap();
            let cross_f_12: [FieldElement; 3] = cross_12.0.try_into().unwrap();
            let cross_g_12: [FieldElement; 3] = cross_12.1.try_into().unwrap();
            let cross_f_21: [FieldElement; 3] = cross_21.0.try_into().unwrap();
            let cross_g_21: [FieldElement; 3] = cross_21.1.try_into().unwrap();

            // Build weights and evaluations with full 4-polynomial layout per weight
            // weights_1 evaluations: [f1, g1, cross_f12, cross_g12] per weight
            let (mut weights_1, mut evaluations_1) = prepare_weights_and_evaluations_dual::<3>(
                self.m,
                &f_sums_1,
                &g_sums_1,
                &cross_f_12,
                &cross_g_12,
            );
            // weights_2 evaluations: [cross_f21, cross_g21, f2, g2] per weight
            let (weights_2, evaluations_2) = prepare_weights_and_evaluations_dual::<3>(
                self.m,
                &cross_f_21,
                &cross_g_21,
                &f_sums_2,
                &g_sums_2,
            );

            let public_hint: (FieldElement, FieldElement, FieldElement, FieldElement) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("failed to read WHIR public weights query answer"))?;

            if !public_inputs.is_empty() {
                update_weights_and_evaluations_dual(
                    self.m,
                    &mut weights_1,
                    &mut evaluations_1,
                    public_hint,
                    public_inputs.len(),
                    public_weights_vector_random,
                );
            }

            let mut all_weights = weights_1;
            all_weights.extend(weights_2);

            let mut all_evaluations = evaluations_1;
            all_evaluations.extend(evaluations_2);

            let weight_refs: Vec<&dyn Weights<FieldElement>> = all_weights
                .iter()
                .map(|w| w as &dyn Weights<FieldElement>)
                .collect();
            let commitment_refs: Vec<&Commitment<FieldElement>> =
                vec![&commitment_1, &commitment_2];

            let (whir_folding_randomness, deferred_evals) = run_whir_pcs_verifier(
                &mut arthur,
                &self.whir_witness,
                &commitment_refs,
                &weight_refs,
                &all_evaluations,
            )
            .context("while verifying WHIR batch proof")?;

            (
                f_sums_1[0] + f_sums_2[0],
                f_sums_1[1] + f_sums_2[1],
                f_sums_1[2] + f_sums_2[2],
                whir_folding_randomness.0.to_vec(),
                deferred_evals,
                public_weights_vector_random,
            )
        } else {
            // Single commitment mode
            let sums: (Vec<FieldElement>, Vec<FieldElement>) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("Failed to read sums hint"))?;
            let whir_sums: ([FieldElement; 3], [FieldElement; 3]) =
                (sums.0.try_into().unwrap(), sums.1.try_into().unwrap());

            let (mut weights, mut evaluations) =
                prepare_weights_and_evaluations::<3>(self.m, &whir_sums);

            let whir_public_weights_query_answer: (FieldElement, FieldElement) = arthur
                .prover_hint_ark()
                .map_err(|_| anyhow::anyhow!("failed to read WHIR public weights query answer"))?;
            if !public_inputs.is_empty() {
                update_weights_and_evaluations(
                    self.m,
                    &mut weights,
                    &mut evaluations,
                    whir_public_weights_query_answer,
                    public_inputs.len(),
                    public_weights_vector_random,
                );
            }

            let weight_refs: Vec<&dyn Weights<FieldElement>> = weights
                .iter()
                .map(|w| w as &dyn Weights<FieldElement>)
                .collect();

            let (whir_folding_randomness, deferred_evals) = run_whir_pcs_verifier(
                &mut arthur,
                &self.whir_witness,
                &[&commitment_1],
                &weight_refs,
                &evaluations,
            )
            .context("while verifying WHIR proof")?;

            (
                whir_sums.0[0],
                whir_sums.0[1],
                whir_sums.0[2],
                whir_folding_randomness.0.to_vec(),
                deferred_evals,
                public_weights_vector_random,
            )
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

        // Check deferred linear constraints.
        // The public weight is Geometric (non-deferred), so it's not in the deferred
        // list.
        let offset = 0;

        // Linear deferred
        if self.num_challenges > 0 {
            assert!(
                deferred_evals.len() == offset + 6,
                "Deferred evals length does not match"
            );

            let matrix_extension_evals = evaluate_r1cs_matrix_extension_batch(
                r1cs,
                &data_from_sumcheck_verifier.alpha,
                &whir_folding_randomness,
                self.w1_size,
            );
            for i in 0..6 {
                ensure!(
                    matrix_extension_evals[i] == deferred_evals[offset + i],
                    "Matrix extension evaluation {} does not match deferred value",
                    i
                );
            }
        } else {
            assert!(
                deferred_evals.len() == offset + 3,
                "Deferred evals length does not match"
            );

            let matrix_extension_evals = evaluate_r1cs_matrix_extension(
                r1cs,
                &data_from_sumcheck_verifier.alpha,
                &whir_folding_randomness,
            );

            for i in 0..3 {
                ensure!(
                    matrix_extension_evals[i] == deferred_evals[offset + i],
                    "Matrix extension evaluation {} does not match deferred value",
                    i
                );
            }
        }

        Ok(())
    }
}

/// Build weights and evaluations for the verifier, mirroring the prover's
/// `create_weights_and_evaluations_for_two_polynomials`.
///
/// Each weight is a linear constraint with a zero-filled evaluation list (the
/// verifier doesn't know the polynomial, so the weight itself is deferred).
/// The claimed evaluations come from the prover's hints: f_sums and g_sums
/// interleaved as [f_sum_i, g_sum_i] for each constraint.
fn prepare_weights_and_evaluations<const N: usize>(
    m: usize,
    whir_query_answer_sums: &([FieldElement; N], [FieldElement; N]),
) -> (Vec<Covector<FieldElement>>, Vec<FieldElement>) {
    let cfg_nv = m + 1; // whir_witness uses m+1 variables (matching prover's cfg_nv)
    let final_len = 1usize << cfg_nv;

    let mut weights = Vec::with_capacity(N);
    let mut evaluations = Vec::with_capacity(N * 2);

    for i in 0..N {
        let weight = Covector::new(vec![FieldElement::zero(); final_len]);
        weights.push(weight);

        // Each weight evaluates against 2 polynomials (masked + random) → 2 evaluations
        // per weight
        evaluations.push(whir_query_answer_sums.0[i]); // f_sum (masked polynomial)
        evaluations.push(whir_query_answer_sums.1[i]); // g_sum (random
                                                       // polynomial)
    }

    (weights, evaluations)
}

/// Add a public weight constraint at the front, mirroring the prover's
/// `compute_public_weight_evaluations` which inserts at position 0.
///
/// The weight must be `Weights::geometric` to match the prover (not
/// `Weights::linear`), because `Geometric` is non-deferred and the verifier
/// computes its value itself.
fn update_weights_and_evaluations(
    m: usize,
    weights: &mut Vec<Covector<FieldElement>>,
    evaluations: &mut Vec<FieldElement>,
    whir_public_weights_query_answer: (FieldElement, FieldElement),
    public_inputs_len: usize,
    x: FieldElement,
) {
    let domain_size = 1usize << m;
    let mut public_weight_evals = vec![FieldElement::zero(); domain_size];
    let mut current_pow = FieldElement::one();
    for slot in public_weight_evals.iter_mut().take(public_inputs_len) {
        *slot = current_pow;
        current_pow *= x;
    }
    let mut public_weight = Covector::new(public_weight_evals);
    public_weight.deferred = false;
    let (public_f_sum, public_g_sum) = whir_public_weights_query_answer;
    weights.insert(0, public_weight);
    evaluations.insert(0, public_g_sum);
    evaluations.insert(0, public_f_sum);
}

/// Build weights and evaluations for the dual-commitment verifier path.
///
/// Each weight produces 4 evaluations (one per polynomial across both
/// commitments): [eval_c1_masked, eval_c1_random, eval_c2_masked,
/// eval_c2_random]. This matches whir's row-major evaluation matrix layout.
fn prepare_weights_and_evaluations_dual<const N: usize>(
    m: usize,
    evals_c1_masked: &[FieldElement; N],
    evals_c1_random: &[FieldElement; N],
    evals_c2_masked: &[FieldElement; N],
    evals_c2_random: &[FieldElement; N],
) -> (Vec<Covector<FieldElement>>, Vec<FieldElement>) {
    let cfg_nv = m + 1;
    let final_len = 1usize << cfg_nv;

    let mut weights = Vec::with_capacity(N);
    let mut evaluations = Vec::with_capacity(N * 4);

    for i in 0..N {
        let weight = Covector::new(vec![FieldElement::zero(); final_len]);
        weights.push(weight);

        evaluations.push(evals_c1_masked[i]);
        evaluations.push(evals_c1_random[i]);
        evaluations.push(evals_c2_masked[i]);
        evaluations.push(evals_c2_random[i]);
    }

    (weights, evaluations)
}

/// Add a public weight for dual-commitment at the front, with 4 evaluations.
/// Must use `Weights::geometric` to match the prover's non-deferred weight
/// type.
fn update_weights_and_evaluations_dual(
    m: usize,
    weights: &mut Vec<Covector<FieldElement>>,
    evaluations: &mut Vec<FieldElement>,
    public_hint: (FieldElement, FieldElement, FieldElement, FieldElement),
    public_inputs_len: usize,
    x: FieldElement,
) {
    let domain_size = 1usize << m;
    let mut public_weight_evals = vec![FieldElement::zero(); domain_size];
    let mut current_pow = FieldElement::one();
    for slot in public_weight_evals.iter_mut().take(public_inputs_len) {
        *slot = current_pow;
        current_pow *= x;
    }
    let mut public_weight = Covector::new(public_weight_evals);
    public_weight.deferred = false;
    let (f1, g1, f2, g2) = public_hint;
    weights.insert(0, public_weight);
    evaluations.insert(0, g2);
    evaluations.insert(0, f2);
    evaluations.insert(0, g1);
    evaluations.insert(0, f1);
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<'_, SkyscraperSponge>,
    m_0: usize,
    whir_for_spartan_blinding_config: &WhirConfig,
) -> Result<DataFromSumcheckVerifier> {
    let r: Vec<FieldElement> = arthur.verifier_message_vec(m_0);

    let commitment = whir_for_spartan_blinding_config
        .receive_commitment(arthur)
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

    let values_of_polynomial_sums: [FieldElement; 2] = [
        arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("Failed to read polynomial sum"))?,
        arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("Failed to read polynomial sum"))?,
    ];

    let blinding_nv = whir_for_spartan_blinding_config.initial_num_variables();

    let (blinding_weights, blinding_evaluations) = prepare_weights_and_evaluations::<1>(
        blinding_nv - 1, // m parameter (cfg_nv = m+1)
        &([values_of_polynomial_sums[0]], [
            values_of_polynomial_sums[1]
        ]),
    );

    let blinding_weight_refs: Vec<&dyn Weights<FieldElement>> = blinding_weights
        .iter()
        .map(|w| w as &dyn Weights<FieldElement>)
        .collect();

    run_whir_pcs_verifier(
        arthur,
        whir_for_spartan_blinding_config,
        &[&commitment],
        &blinding_weight_refs,
        &blinding_evaluations,
    )
    .context("while verifying WHIR")?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * values_of_polynomial_sums[0];

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        last_sumcheck_val: f_at_alpha,
    })
}

#[instrument(skip_all)]
pub fn run_whir_pcs_verifier(
    arthur: &mut VerifierState<'_, SkyscraperSponge>,
    params: &WhirConfig,
    commitments: &[&Commitment<FieldElement>],
    weights: &[&dyn Weights<FieldElement>],
    evaluations: &[FieldElement],
) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
    let (folding_randomness, deferred) =
        params
            .verify(arthur, commitments, weights, evaluations)
            .map_err(|_| anyhow::anyhow!("WHIR verification failed"))?;
    Ok((folding_randomness, deferred))
}

fn evaluate_r1cs_matrix_extension(
    r1cs: &R1CS,
    row_rand: &[FieldElement],
    col_rand: &[FieldElement],
) -> [FieldElement; 3] {
    let row_eval = calculate_evaluations_over_boolean_hypercube_for_eq(row_rand.to_vec());
    let col_eval = calculate_evaluations_over_boolean_hypercube_for_eq(col_rand.to_vec());

    let mut ans_a = FieldElement::zero();
    let mut ans_b = FieldElement::zero();
    let mut ans_c = FieldElement::zero();

    for ((row, col), val) in r1cs.a().iter() {
        ans_a += val * row_eval[row] * col_eval[col];
    }

    for ((row, col), val) in r1cs.b().iter() {
        ans_b += val * row_eval[row] * col_eval[col];
    }

    for ((row, col), val) in r1cs.c().iter() {
        ans_c += val * row_eval[row] * col_eval[col];
    }

    [ans_a, ans_b, ans_c]
}

fn evaluate_r1cs_matrix_extension_batch(
    r1cs: &R1CS,
    row_rand: &[FieldElement],
    col_rand: &[FieldElement],
    w1_size: usize,
) -> [FieldElement; 6] {
    let row_eval = calculate_evaluations_over_boolean_hypercube_for_eq(row_rand.to_vec());
    let col_eval = calculate_evaluations_over_boolean_hypercube_for_eq(col_rand.to_vec());

    let mut ans = [FieldElement::zero(); 6];

    // Evaluate matrices - split by column based on w1_size
    for ((row, col), val) in r1cs.a().iter() {
        if col < w1_size {
            ans[0] += val * row_eval[row] * col_eval[col];
        } else {
            ans[3] += val * row_eval[row] * col_eval[col - w1_size];
        }
    }

    for ((row, col), val) in r1cs.b().iter() {
        if col < w1_size {
            ans[1] += val * row_eval[row] * col_eval[col];
        } else {
            ans[4] += val * row_eval[row] * col_eval[col - w1_size];
        }
    }

    for ((row, col), val) in r1cs.c().iter() {
        if col < w1_size {
            ans[2] += val * row_eval[row] * col_eval[col];
        } else {
            ans[5] += val * row_eval[row] * col_eval[col - w1_size];
        }
    }

    ans
}
