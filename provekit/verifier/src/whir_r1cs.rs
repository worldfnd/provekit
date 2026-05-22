use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        prefix_covector::{
            build_combined_prefix_covector, expand_powers, make_challenge_weight,
            make_public_weight, rlc_powers, OffsetCovector,
        },
        utils::sumcheck::{
            calculate_eq, eval_cubic_poly, multiply_transposed_by_eq_alpha, transpose_r1cs_matrices,
        },
        FieldElement, PublicInputs, TranscriptSponge, WhirR1CSProof, WhirR1CSScheme, R1CS,
    },
    tracing::instrument,
    whir::{
        algebra::{dot, linear_form::LinearForm},
        transcript::{Proof, VerifierMessage, VerifierState},
    },
};

pub struct DataFromSumcheckVerifier {
    r:             Vec<FieldElement>,
    alpha:         Vec<FieldElement>,
    blinding_eval: FieldElement,
    f_at_alpha:    FieldElement,
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
        let instance = public_inputs.hash_bytes();
        let ds = self.create_domain_separator().instance(&instance);
        let whir_proof = Proof {
            narg_string: proof.narg_string.clone(),
            hints: proof.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: proof.pattern.clone(),
        };
        let mut arthur = VerifierState::new(&ds, &whir_proof, TranscriptSponge::default());

        let commitment_1 = self
            .whir_witness
            .receive_commitments(&mut arthur)
            .map_err(|_| anyhow::anyhow!("Failed to parse commitment 1"))?;

        let (commitment_2, logup_challenges) = if self.num_challenges > 0 {
            let logup_challenges: Vec<FieldElement> =
                arthur.verifier_message_vec(self.num_challenges);
            (
                Some(
                    self.whir_witness
                        .receive_commitments(&mut arthur)
                        .map_err(|_| anyhow::anyhow!("Failed to parse commitment 2"))?,
                ),
                logup_challenges,
            )
        } else {
            (None, Vec::new())
        };

        let (transposed, sumcheck_result) = rayon::join(
            || transpose_r1cs_matrices(r1cs),
            || run_sumcheck_verifier(&mut arthur, self.m_0),
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

        let blinding_eval = data_from_sumcheck_verifier.blinding_eval;
        let blinding_weights = expand_powers::<4>(&data_from_sumcheck_verifier.alpha);
        let domain_size = 1usize << self.m;
        let blinding_covector = OffsetCovector::new(blinding_weights, self.w1_size, domain_size);

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

            let evals_1: [FieldElement; 3] = [
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_1[0]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_1[1]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_1[2]"))?,
            ];
            let evals_2: [FieldElement; 3] = [
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_2[0]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_2[1]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals_2[2]"))?,
            ];

            // Mirror prover: read optional public/challenge evals first so the
            // FS state matches at the inner_rlc sample below.
            let public_1_eval = if !public_inputs.is_empty() {
                let public_1: FieldElement = arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read public_1"))?;
                verify_public_input_binding(public_1, x, public_inputs)?;
                Some(public_1)
            } else {
                None
            };

            // Challenge binding: read the prover's claimed evaluation and verify
            // that it matches the expected inner product of challenges with the
            // committed w2 polynomial.
            let challenge_binding = if !self.challenge_offsets.is_empty() {
                let challenge_eval: FieldElement = arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read challenge eval"))?;
                verify_challenge_binding(challenge_eval, x, &logup_challenges)?;
                Some(challenge_eval)
            } else {
                None
            };

            // Mirror prover's direct-RLC sample. One challenge collapses each
            // commitment's (A, B, C) triple into a single linear form.
            let powers = rlc_powers::<3>(arthur.verifier_message());
            let combined_eval_1 = dot(&powers, &evals_1);
            let combined_eval_2 = dot(&powers, &evals_2);
            let combined_lf_1 = build_combined_prefix_covector(alphas_1, &powers, domain_size);
            let combined_lf_2 = build_combined_prefix_covector(alphas_2, &powers, domain_size);

            let public_weight_1 = public_1_eval
                .map(|_| make_public_weight(x, public_inputs.len(), self.m));
            let challenge_weight = challenge_binding
                .map(|_| make_challenge_weight(x, &self.challenge_offsets, self.m));

            let mut weight_refs_1: Vec<&dyn LinearForm<FieldElement>> = Vec::new();
            let mut evaluations_1: Vec<FieldElement> = Vec::new();
            if let (Some(ref pw), Some(pe)) = (&public_weight_1, public_1_eval) {
                weight_refs_1.push(pw as &dyn LinearForm<FieldElement>);
                evaluations_1.push(pe);
            }
            weight_refs_1.push(&combined_lf_1 as &dyn LinearForm<FieldElement>);
            evaluations_1.push(combined_eval_1);
            weight_refs_1.push(&blinding_covector as &dyn LinearForm<FieldElement>);
            evaluations_1.push(blinding_eval);

            self.whir_witness
                .verify(&mut arthur, &weight_refs_1, &evaluations_1, &commitment_1)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed for c1"))?;

            let mut weight_refs_2: Vec<&dyn LinearForm<FieldElement>> =
                vec![&combined_lf_2 as &dyn LinearForm<FieldElement>];
            let mut evaluations_2: Vec<FieldElement> = vec![combined_eval_2];
            if let (Some(ref cw), Some(ce)) = (&challenge_weight, challenge_binding) {
                weight_refs_2.push(cw as &dyn LinearForm<FieldElement>);
                evaluations_2.push(ce);
            }
            self.whir_witness
                .verify(&mut arthur, &weight_refs_2, &evaluations_2, &commitment_2)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed for c2"))?;

            (
                evals_1[0] + evals_2[0],
                evals_1[1] + evals_2[1],
                evals_1[2] + evals_2[2],
            )
        } else {
            let evals: [FieldElement; 3] = [
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals[0]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals[1]"))?,
                arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read evals[2]"))?,
            ];

            // Mirror prover: read public eval (if any), then sample inner_rlc
            // and collapse the three R1CS row-covectors into one.
            let public_eval = if !public_inputs.is_empty() {
                let pe: FieldElement = arthur
                    .prover_message()
                    .map_err(|_| anyhow::anyhow!("Failed to read public eval"))?;
                verify_public_input_binding(pe, x, public_inputs)?;
                Some(pe)
            } else {
                None
            };

            let powers = rlc_powers::<3>(arthur.verifier_message());
            let combined_eval = dot(&powers, &evals);
            let combined_lf = build_combined_prefix_covector(alphas, &powers, domain_size);
            let public_weight =
                public_eval.map(|_| make_public_weight(x, public_inputs.len(), self.m));

            let mut weight_refs: Vec<&dyn LinearForm<FieldElement>> = Vec::new();
            let mut evaluations: Vec<FieldElement> = Vec::new();
            if let (Some(ref pw), Some(pe)) = (&public_weight, public_eval) {
                weight_refs.push(pw as &dyn LinearForm<FieldElement>);
                evaluations.push(pe);
            }
            weight_refs.push(&combined_lf as &dyn LinearForm<FieldElement>);
            evaluations.push(combined_eval);
            weight_refs.push(&blinding_covector as &dyn LinearForm<FieldElement>);
            evaluations.push(blinding_eval);

            self.whir_witness
                .verify(&mut arthur, &weight_refs, &evaluations, &commitment_1)
                .map_err(|_| anyhow::anyhow!("WHIR verification failed"))?;

            (evals[0], evals[1], evals[2])
        };

        ensure!(
            data_from_sumcheck_verifier.f_at_alpha
                == (az_at_alpha * bz_at_alpha - cz_at_alpha)
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        arthur
            .check_eof()
            .map_err(|_| anyhow::anyhow!("Proof contains unparsed trailing bytes"))
    }
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    m_0: usize,
) -> Result<DataFromSumcheckVerifier> {
    let r: Vec<FieldElement> = arthur.verifier_message_vec(m_0);

    let sum_g: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("Failed to read sum_g"))?;

    let rho: FieldElement = arthur.verifier_message();

    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g;

    let mut alpha = vec![FieldElement::zero(); m_0];

    for item in &mut alpha {
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
        .map_err(|_| anyhow::anyhow!("Failed to read blinding eval"))?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * blinding_eval;

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        blinding_eval,
        f_at_alpha,
    })
}

/// Verify that `challenge_eval == Σ xⁱ · challenges[i]`.
///
/// The prover sends `challenge_eval` as a transcript-bound message, and WHIR
/// verifies that it equals the inner product of `make_challenge_weight(x, …)`
/// with the committed w2 polynomial.  This function independently recomputes
/// the expected value from the Fiat-Shamir `challenges` (which the verifier
/// already knows) and checks equality, ensuring the committed w2 polynomial
/// stores the correct challenge values at the declared offsets.
fn verify_challenge_binding(
    challenge_eval: FieldElement,
    x: FieldElement,
    challenges: &[FieldElement],
) -> Result<()> {
    let mut expected = FieldElement::zero();
    let mut x_pow = FieldElement::one();
    for &ch in challenges {
        expected += x_pow * ch;
        x_pow *= x;
    }
    ensure!(
        challenge_eval == expected,
        "Challenge binding check failed: prover's challenge_eval does not match expected value"
    );
    Ok(())
}

/// Verify that the prover's claimed public evaluation matches the known public
/// inputs. The weight covers positions `[0, 1, ..., N]` where position 0 is the
/// R1CS constant `1` and positions `1..=N` are the public inputs.
fn verify_public_input_binding(
    public_eval: FieldElement,
    x: FieldElement,
    public_inputs: &PublicInputs,
) -> Result<()> {
    let mut expected = FieldElement::one();
    let mut x_pow = x;
    for &pi in &public_inputs.0 {
        expected += x_pow * pi;
        x_pow *= x;
    }
    ensure!(
        public_eval == expected,
        "Public input binding check failed: expected {expected:?}, got {public_eval:?}"
    );
    Ok(())
}
