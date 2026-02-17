use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        utils::sumcheck::{
            calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_cubic_poly,
        },
        FieldElement, PublicInputs, TranscriptSponge, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig,
        R1CS,
    },
    tracing::instrument,
    whir::{
        algebra::linear_form::{Covector, LinearForm},
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
        let mut arthur = VerifierState::new(&ds, &whir_proof, TranscriptSponge::default());

        let whir_zk_witness = self.whir_zk_witness();

        let commitment_1 = whir_zk_witness
            .receive_commitments(&mut arthur, 1)
            .map_err(|_| anyhow::anyhow!("Failed to parse commitment 1"))?;

        let commitment_2 = if self.num_challenges > 0 {
            let _logup_challenges: Vec<FieldElement> =
                arthur.verifier_message_vec(self.num_challenges);
            Some(
                whir_zk_witness
                    .receive_commitments(&mut arthur, 1)
                    .map_err(|_| anyhow::anyhow!("Failed to parse commitment 2"))?,
            )
        } else {
            None
        };

        let whir_zk_spartan = self.whir_zk_spartan();
        let data_from_sumcheck_verifier =
            run_sumcheck_verifier(&mut arthur, self.m_0, &whir_zk_spartan)
                .context("while verifying sumcheck")?;

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

        if let Some(commitment_2) = commitment_2 {
            let (
                az_at_alpha,
                bz_at_alpha,
                cz_at_alpha,
                folding_rand_1,
                folding_rand_2,
                deferred_evals,
            ) = verify_dual(
                &mut arthur,
                &whir_zk_witness,
                &commitment_1,
                &commitment_2,
                public_inputs,
                public_weights_vector_random,
                self.m,
            )?;

            ensure!(
                data_from_sumcheck_verifier.last_sumcheck_val
                    == (az_at_alpha * bz_at_alpha - cz_at_alpha)
                        * calculate_eq(
                            &data_from_sumcheck_verifier.r,
                            &data_from_sumcheck_verifier.alpha
                        ),
                "last sumcheck value does not match"
            );

            ensure!(
                deferred_evals.len() == 6,
                "Deferred evals length does not match"
            );

            let matrix_extension_evals = evaluate_r1cs_matrix_extension_dual(
                r1cs,
                &data_from_sumcheck_verifier.alpha,
                &folding_rand_1,
                &folding_rand_2,
                self.w1_size,
            );
            for i in 0..6 {
                ensure!(
                    matrix_extension_evals[i] == deferred_evals[i],
                    "Matrix extension evaluation {} does not match deferred value",
                    i
                );
            }
        } else {
            let (az_at_alpha, bz_at_alpha, cz_at_alpha, whir_folding_randomness, deferred_evals) =
                verify_single(
                    &mut arthur,
                    &whir_zk_witness,
                    &commitment_1,
                    public_inputs,
                    public_weights_vector_random,
                    self.m,
                )?;

            ensure!(
                data_from_sumcheck_verifier.last_sumcheck_val
                    == (az_at_alpha * bz_at_alpha - cz_at_alpha)
                        * calculate_eq(
                            &data_from_sumcheck_verifier.r,
                            &data_from_sumcheck_verifier.alpha
                        ),
                "last sumcheck value does not match"
            );

            ensure!(
                deferred_evals.len() == 3,
                "Deferred evals length does not match"
            );

            let matrix_extension_evals = evaluate_r1cs_matrix_extension(
                r1cs,
                &data_from_sumcheck_verifier.alpha,
                &whir_folding_randomness,
            );

            for i in 0..3 {
                ensure!(
                    matrix_extension_evals[i] == deferred_evals[i],
                    "Matrix extension evaluation {} does not match deferred value",
                    i
                );
            }
        }

        Ok(())
    }
}

type VerifyResult = Result<(
    FieldElement,
    FieldElement,
    FieldElement,
    Vec<FieldElement>,
    Vec<FieldElement>,
)>;

type DualVerifyResult = Result<(
    FieldElement,
    FieldElement,
    FieldElement,
    Vec<FieldElement>,
    Vec<FieldElement>,
    Vec<FieldElement>,
)>;

fn verify_single(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    whir_zk_config: &WhirZkConfig,
    commitment: &whir::protocols::whir_zk::Commitment<FieldElement>,
    public_inputs: &PublicInputs,
    x: FieldElement,
    m: usize,
) -> VerifyResult {
    let poly_len = 1usize << m;

    let eval_values: Vec<FieldElement> = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read eval_values hint"))?;
    ensure!(eval_values.len() == 3, "Expected 3 evaluation values");

    let public_eval: FieldElement = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read public_eval hint"))?;

    let mut weights: Vec<Covector<FieldElement>> = Vec::with_capacity(4);
    let mut all_evals: Vec<FieldElement> = Vec::new();

    if !public_inputs.is_empty() {
        let mut public_weight_vec = vec![FieldElement::zero(); poly_len];
        let mut current_pow = FieldElement::one();
        for slot in public_weight_vec.iter_mut().take(public_inputs.len()) {
            *slot = current_pow;
            current_pow *= x;
        }
        let mut pw = Covector::new(public_weight_vec);
        pw.deferred = false;
        weights.push(pw);
        all_evals.push(public_eval);
    }

    for &ev in &eval_values {
        let w = Covector::new(vec![FieldElement::zero(); poly_len]);
        weights.push(w);
        all_evals.push(ev);
    }

    let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();

    let (whir_folding_randomness, deferred_evals) = whir_zk_config
        .verify(&mut *arthur, commitment, &weight_refs, &all_evals)
        .map_err(|_| anyhow::anyhow!("WHIR ZK verification failed"))?;

    Ok((
        eval_values[0],
        eval_values[1],
        eval_values[2],
        whir_folding_randomness.0.to_vec(),
        deferred_evals,
    ))
}

fn verify_dual(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    whir_zk_config: &WhirZkConfig,
    commitment_1: &whir::protocols::whir_zk::Commitment<FieldElement>,
    commitment_2: &whir::protocols::whir_zk::Commitment<FieldElement>,
    public_inputs: &PublicInputs,
    x: FieldElement,
    m: usize,
) -> DualVerifyResult {
    let poly_len = 1usize << m;

    let evals_1: Vec<FieldElement> = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read evals_1 hint"))?;
    let evals_2: Vec<FieldElement> = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read evals_2 hint"))?;
    ensure!(
        evals_1.len() == 3 && evals_2.len() == 3,
        "Expected 3 evaluation values each"
    );

    let (public_eval_1, public_eval_2): (FieldElement, FieldElement) = arthur
        .prover_hint_ark()
        .map_err(|_| anyhow::anyhow!("Failed to read public eval hints"))?;

    let build_weights_and_evals = |evals: &[FieldElement], public_eval: FieldElement| {
        let mut weights: Vec<Covector<FieldElement>> = Vec::with_capacity(4);
        let mut all_evals: Vec<FieldElement> = Vec::new();

        if !public_inputs.is_empty() {
            let mut public_weight_vec = vec![FieldElement::zero(); poly_len];
            let mut current_pow = FieldElement::one();
            for slot in public_weight_vec.iter_mut().take(public_inputs.len()) {
                *slot = current_pow;
                current_pow *= x;
            }
            let mut pw = Covector::new(public_weight_vec);
            pw.deferred = false;
            weights.push(pw);
            all_evals.push(public_eval);
        }

        for &ev in evals {
            let w = Covector::new(vec![FieldElement::zero(); poly_len]);
            weights.push(w);
            all_evals.push(ev);
        }

        (weights, all_evals)
    };

    let (weights_1, all_evals_1) = build_weights_and_evals(&evals_1, public_eval_1);
    let (weights_2, all_evals_2) = build_weights_and_evals(&evals_2, public_eval_2);

    let weight_refs_1: Vec<&dyn LinearForm<FieldElement>> = weights_1
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();

    let (whir_folding_randomness_1, deferred_evals_1) = whir_zk_config
        .verify(&mut *arthur, commitment_1, &weight_refs_1, &all_evals_1)
        .map_err(|_| anyhow::anyhow!("WHIR ZK verification failed for commitment 1"))?;

    let weight_refs_2: Vec<&dyn LinearForm<FieldElement>> = weights_2
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();

    let (whir_folding_randomness_2, deferred_evals_2) = whir_zk_config
        .verify(&mut *arthur, commitment_2, &weight_refs_2, &all_evals_2)
        .map_err(|_| anyhow::anyhow!("WHIR ZK verification failed for commitment 2"))?;

    ensure!(
        deferred_evals_1.len() == 3 && deferred_evals_2.len() == 3,
        "Expected 3 deferred evals per commitment"
    );

    let mut deferred_evals = Vec::with_capacity(6);
    deferred_evals.extend_from_slice(&deferred_evals_1);
    deferred_evals.extend_from_slice(&deferred_evals_2);

    Ok((
        evals_1[0] + evals_2[0],
        evals_1[1] + evals_2[1],
        evals_1[2] + evals_2[2],
        whir_folding_randomness_1.0.to_vec(),
        whir_folding_randomness_2.0.to_vec(),
        deferred_evals,
    ))
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    m_0: usize,
    whir_zk_spartan: &WhirZkConfig,
) -> Result<DataFromSumcheckVerifier> {
    let r: Vec<FieldElement> = arthur.verifier_message_vec(m_0);

    let commitment = whir_zk_spartan
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

    let blinding_eval: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("Failed to read blinding evaluation"))?;

    let blinding_nv = whir_zk_spartan.num_witness_variables();
    let blinding_poly_len = 1usize << blinding_nv;

    let blinding_weight = Covector::new(vec![FieldElement::zero(); blinding_poly_len]);

    let blinding_weight_refs: Vec<&dyn LinearForm<FieldElement>> =
        vec![&blinding_weight as &dyn LinearForm<FieldElement>];

    whir_zk_spartan
        .verify(arthur, &commitment, &blinding_weight_refs, &[blinding_eval])
        .map_err(|_| anyhow::anyhow!("WHIR ZK verification of spartan blinding failed"))?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * blinding_eval;

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        last_sumcheck_val: f_at_alpha,
    })
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

fn evaluate_r1cs_matrix_extension_dual(
    r1cs: &R1CS,
    row_rand: &[FieldElement],
    col_rand_1: &[FieldElement],
    col_rand_2: &[FieldElement],
    w1_size: usize,
) -> [FieldElement; 6] {
    let row_eval = calculate_evaluations_over_boolean_hypercube_for_eq(row_rand.to_vec());
    let col_eval_1 = calculate_evaluations_over_boolean_hypercube_for_eq(col_rand_1.to_vec());
    let col_eval_2 = calculate_evaluations_over_boolean_hypercube_for_eq(col_rand_2.to_vec());

    let mut ans = [FieldElement::zero(); 6];

    for ((row, col), val) in r1cs.a().iter() {
        if col < w1_size {
            ans[0] += val * row_eval[row] * col_eval_1[col];
        } else {
            ans[3] += val * row_eval[row] * col_eval_2[col - w1_size];
        }
    }

    for ((row, col), val) in r1cs.b().iter() {
        if col < w1_size {
            ans[1] += val * row_eval[row] * col_eval_1[col];
        } else {
            ans[4] += val * row_eval[row] * col_eval_2[col - w1_size];
        }
    }

    for ((row, col), val) in r1cs.c().iter() {
        if col < w1_size {
            ans[2] += val * row_eval[row] * col_eval_1[col];
        } else {
            ans[5] += val * row_eval[row] * col_eval_2[col - w1_size];
        }
    }

    ans
}
