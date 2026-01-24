use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::{
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_cubic_poly,
            },
            zk_utils::geometric_till,
        },
        FieldElement, PublicInputs, WhirConfig, WhirR1CSProof, WhirR1CSScheme, R1CS,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
        VerifierState,
    },
    tracing::instrument,
    whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader},
            statement::{Statement, Weights},
            utils::HintDeserialize,
            verifier::Verifier,
        },
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
    #[allow(unused)]
    fn verify(
        &self,
        proof: &WhirR1CSProof,
        public_inputs: &PublicInputs,
        r1cs: &R1CS,
    ) -> Result<()> {
        let io = self.create_io_pattern();
        let mut arthur = io.to_verifier_state(&proof.transcript);

        let commitment_reader = CommitmentReader::new(&self.whir_witness);
        let parsed_commitment_1 = commitment_reader.parse_commitment(&mut arthur)?;

        // Parse second commitment only if we have challenges
        let parsed_commitment_2 = if self.num_challenges > 0 {
            let mut _logup_challenges = vec![FieldElement::zero(); self.num_challenges];
            arthur.fill_challenge_scalars(&mut _logup_challenges)?;
            Some(commitment_reader.parse_commitment(&mut arthur)?)
        } else {
            None
        };

        // Sumcheck verification (common to both paths)
        let data_from_sumcheck_verifier =
            run_sumcheck_verifier(&mut arthur, self.m_0, &self.whir_for_hiding_spartan)
                .context("while verifying sumcheck")?;

        // Verify public inputs hash
        let mut public_inputs_hash_buf = [FieldElement::zero()];
        arthur.fill_next_scalars(&mut public_inputs_hash_buf)?;
        let expected_public_inputs_hash = public_inputs.hash();
        ensure!(
            public_inputs_hash_buf[0] == expected_public_inputs_hash,
            "Public inputs hash mismatch: expected {:?}, got {:?}",
            expected_public_inputs_hash,
            public_inputs_hash_buf[0]
        );
        let mut public_weights_vector_random_buf = [FieldElement::zero()];
        arthur.fill_challenge_scalars(&mut public_weights_vector_random_buf)?;

        // Read hints and verify WHIR proof
        let (
            az_at_alpha,
            bz_at_alpha,
            cz_at_alpha,
            whir_folding_randomness,
            deferred_evals,
            public_weights_challenge,
        ) = if let Some(parsed_commitment_2) = parsed_commitment_2 {
            // Dual commitment mode
            let sums_1: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;
            let sums_2: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;

            let whir_sums_1: ([FieldElement; 3], [FieldElement; 3]) =
                (sums_1.0.try_into().unwrap(), sums_1.1.try_into().unwrap());
            let whir_sums_2: ([FieldElement; 3], [FieldElement; 3]) =
                (sums_2.0.try_into().unwrap(), sums_2.1.try_into().unwrap());

            let mut statement_1 = prepare_statement_for_witness_verifier::<3>(
                self.m,
                &parsed_commitment_1,
                &whir_sums_1,
            );
            let statement_2 = prepare_statement_for_witness_verifier::<3>(
                self.m,
                &parsed_commitment_2,
                &whir_sums_2,
            );

            let whir_public_weights_query_answer: (FieldElement, FieldElement) = arthur
                .hint()
                .context("failed to read WHIR public weights query answer")?;

            if !public_inputs.is_empty() {
                update_statement_for_witness_verifier(
                    self.m,
                    &mut statement_1,
                    &parsed_commitment_1,
                    whir_public_weights_query_answer,
                );
            }

            let (whir_folding_randomness, deferred_evals) = run_whir_pcs_batch_verifier(
                &mut arthur,
                &self.whir_witness,
                &[parsed_commitment_1, parsed_commitment_2],
                &[statement_1, statement_2],
            )
            .context("while verifying WHIR batch proof")?;

            (
                whir_sums_1.0[0] + whir_sums_2.0[0],
                whir_sums_1.0[1] + whir_sums_2.0[1],
                whir_sums_1.0[2] + whir_sums_2.0[2],
                whir_folding_randomness.0.to_vec(),
                deferred_evals,
                public_weights_vector_random_buf[0],
            )
        } else {
            // Single commitment mode
            let sums: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;
            let whir_sums: ([FieldElement; 3], [FieldElement; 3]) =
                (sums.0.try_into().unwrap(), sums.1.try_into().unwrap());

            let mut statement = prepare_statement_for_witness_verifier::<3>(
                self.m,
                &parsed_commitment_1,
                &whir_sums,
            );

            let whir_public_weights_query_answer: (FieldElement, FieldElement) = arthur
                .hint()
                .context("failed to read WHIR public weights query answer")?;
            if !public_inputs.is_empty() {
                update_statement_for_witness_verifier(
                    self.m,
                    &mut statement,
                    &parsed_commitment_1,
                    whir_public_weights_query_answer,
                );
            }

            let (whir_folding_randomness, deferred_evals) = run_whir_pcs_verifier(
                &mut arthur,
                &parsed_commitment_1,
                &self.whir_witness,
                &statement,
            )
            .context("while verifying WHIR proof")?;

            (
                whir_sums.0[0],
                whir_sums.0[1],
                whir_sums.0[2],
                whir_folding_randomness.0.to_vec(),
                deferred_evals,
                public_weights_vector_random_buf[0],
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

        // Check deferred linear and geometric constraints
        let offset = if public_inputs.is_empty() { 0 } else { 1 };

        // Linear deferred
        if self.num_challenges > 0 {
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

        // Geometric deferred
        if !public_inputs.is_empty() {
            let public_weight_eval = compute_public_weight_evaluation(
                public_inputs,
                &whir_folding_randomness,
                self.whir_witness.mv_parameters.num_variables,
                public_weights_challenge,
            );
            ensure!(
                public_weight_eval == deferred_evals[0],
                "Public weight evaluation does not match deferred value"
            );
        }

        Ok(())
    }
}

fn prepare_statement_for_witness_verifier<const N: usize>(
    m: usize,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    whir_query_answer_sums: &([FieldElement; N], [FieldElement; N]),
) -> Statement<FieldElement> {
    let mut statement_verifier = Statement::<FieldElement>::new(m);
    for i in 0..whir_query_answer_sums.0.len() {
        let claimed_sum = whir_query_answer_sums.0[i]
            + whir_query_answer_sums.1[i] * parsed_commitment.batching_randomness;
        statement_verifier.add_constraint(
            Weights::linear(EvaluationsList::new(vec![FieldElement::zero(); 1 << m])),
            claimed_sum,
        );
    }
    statement_verifier
}

fn update_statement_for_witness_verifier(
    m: usize,
    statement_verifier: &mut Statement<FieldElement>,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    whir_public_weights_query_answer: (FieldElement, FieldElement),
) {
    let (public_f_sum, public_g_sum) = whir_public_weights_query_answer;
    let public_weight = Weights::linear(EvaluationsList::new(vec![FieldElement::zero(); 1 << m]));
    statement_verifier.add_constraint_in_front(
        public_weight,
        public_f_sum + public_g_sum * parsed_commitment.batching_randomness,
    );
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
    whir_for_spartan_blinding_config: &WhirConfig,
) -> Result<DataFromSumcheckVerifier> {
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let commitment_reader = CommitmentReader::new(whir_for_spartan_blinding_config);
    let parsed_commitment = commitment_reader.parse_commitment(arthur)?;

    let mut sum_g_buf = [FieldElement::zero()];
    arthur.fill_next_scalars(&mut sum_g_buf)?;

    let mut rho_buf = [FieldElement::zero()];
    arthur.fill_challenge_scalars(&mut rho_buf)?;
    let rho = rho_buf[0];

    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_buf[0];

    let mut alpha = vec![FieldElement::zero(); m_0];

    for item in alpha.iter_mut().take(m_0) {
        let mut hhat_i = [FieldElement::zero(); 4];
        let mut alpha_i = [FieldElement::zero(); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        *item = alpha_i[0];
        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i[0]);
    }

    let mut values_of_polynomial_sums = [FieldElement::zero(); 2];
    let _ = arthur.fill_next_scalars(&mut values_of_polynomial_sums);

    let statement_verifier = prepare_statement_for_witness_verifier::<1>(
        whir_for_spartan_blinding_config.mv_parameters.num_variables,
        &parsed_commitment,
        &([values_of_polynomial_sums[0]], [
            values_of_polynomial_sums[1]
        ]),
    );

    run_whir_pcs_verifier(
        arthur,
        &parsed_commitment,
        whir_for_spartan_blinding_config,
        &statement_verifier,
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
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    params: &WhirConfig,
    statement_verifier: &Statement<FieldElement>,
) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
    let verifier = Verifier::new(params);
    let (folding_randomness, deferred) = verifier
        .verify(arthur, parsed_commitment, statement_verifier)
        .context("while verifying WHIR")?;
    Ok((folding_randomness, deferred))
}

#[instrument(skip_all)]
pub fn run_whir_pcs_batch_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    params: &WhirConfig,
    parsed_commitments: &[ParsedCommitment<FieldElement, FieldElement>],
    statements: &[Statement<FieldElement>],
) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
    let verifier = Verifier::new(params);
    let (folding_randomness, deferred) = verifier
        .verify_batch(arthur, parsed_commitments, statements)
        .context("while verifying batch WHIR")?;
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

fn compute_public_weight_evaluation(
    public_inputs: &PublicInputs,
    folding_randomness: &[FieldElement],
    m: usize,
    x: FieldElement,
) -> FieldElement {
    let domain_size = 1 << m;
    let mut public_weights = vec![FieldElement::zero(); domain_size];

    let mut current_pow = FieldElement::one();
    for (idx, _) in public_inputs.0.iter().enumerate() {
        public_weights[idx] = current_pow;
        current_pow = current_pow * x;
    }

    let mle = geometric_till(x, public_inputs.len(), folding_randomness);

    #[cfg(test)]
    {
        let eq_polys =
            calculate_evaluations_over_boolean_hypercube_for_eq(folding_randomness.to_vec());
        let sum: FieldElement = public_weights
            .iter()
            .zip(eq_polys.iter())
            .map(|(w, eq)| *w * eq)
            .sum();
        assert!(sum == mle, "Sum does not match mle");
    }

    mle
}
