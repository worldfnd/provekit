use {
    anyhow::{ensure, Result},
    ark_ff::UniformRand,
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperSponge},
        utils::{
            pad_to_power_of_two,
            sumcheck::{
                calculate_evaluations_over_boolean_hypercube_for_eq,
                calculate_external_row_of_r1cs_matrices, calculate_witness_bounds, eval_cubic_poly,
                sumcheck_fold_map_reduce,
            },
            zk_utils::{create_masked_polynomial, generate_random_multilinear_polynomial},
            HALF,
        },
        FieldElement, PublicInputs, WhirConfig, WhirR1CSProof, WhirR1CSScheme, R1CS,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        ProverState,
    },
    std::mem,
    tracing::{info, instrument, warn},
    whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{CommitmentWriter, Witness},
            prover::Prover,
            statement::{Statement, Weights},
            utils::HintSerialize,
        },
    },
};

pub struct WhirR1CSCommitment {
    pub commitment_to_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub masked_polynomial:     EvaluationsList<FieldElement>,
    pub random_polynomial:     EvaluationsList<FieldElement>,
    pub padded_witness:        Vec<FieldElement>,
}

pub trait WhirR1CSProver {
    fn commit(
        &self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        r1cs: &R1CS,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment>;

    fn prove(
        &self,
        merlin: ProverState<SkyscraperSponge, FieldElement>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof>;
}

impl WhirR1CSProver for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn commit(
        &self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        r1cs: &R1CS,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment> {
        let witness_size = if is_w1 {
            self.w1_size
        } else {
            r1cs.num_witnesses() - self.w1_size
        };

        ensure!(
            witness.len() == witness_size,
            "Unexpected witness length for R1CS instance"
        );
        ensure!(
            witness_size <= 1 << self.m,
            "R1CS witness length exceeds scheme capacity"
        );
        ensure!(
            r1cs.num_constraints() <= 1 << self.m_0,
            "R1CS constraints exceed scheme capacity"
        );

        // log2(domain) for WHIR witness evaluations.
        let whir_num_vars = self.whir_witness.mv_parameters.num_variables;

        // Expected evaluation length = 2^(log2(domain) - 1).
        let target_len = 1usize << (whir_num_vars - 1);

        // Pad witness to power-of-two, then extend to target_len with zeros.
        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < target_len {
            padded_witness.resize(target_len, FieldElement::zero());
        }

        let witness_polynomial_evals = EvaluationsList::new(padded_witness.clone());

        let (commitment_to_witness, masked_polynomial, random_polynomial) =
            batch_commit_to_polynomial(
                self.m,
                &self.whir_witness,
                witness_polynomial_evals,
                merlin,
            );

        Ok(WhirR1CSCommitment {
            commitment_to_witness,
            masked_polynomial,
            random_polynomial,
            padded_witness,
        })
    }

    #[instrument(skip_all)]
    fn prove(
        &self,
        mut merlin: ProverState<SkyscraperSponge, FieldElement>,
        r1cs: R1CS,
        mut commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        let is_single = commitments.len() == 1;

        // Reconstruct full witness for sumcheck
        let full_witness: Vec<FieldElement> = if is_single {
            // Truncate padded witness back to actual R1CS witness size
            let mut w = mem::take(&mut commitments[0].padded_witness);
            w.truncate(r1cs.num_witnesses());
            w
        } else {
            let mut w = std::mem::take(&mut commitments[0].padded_witness);
            w.truncate(self.w1_size);
            let w2_len = r1cs.num_witnesses() - self.w1_size;
            w.extend_from_slice(&commitments[1].padded_witness[..w2_len]);
            commitments[1].padded_witness = Vec::new();
            w
        };

        // First round: ZK sumcheck to reduce R1CS to weighted evaluation
        let alpha = run_zk_sumcheck_prover(
            &r1cs,
            &full_witness,
            &mut merlin,
            self.m_0,
            &self.whir_for_hiding_spartan,
        );
        drop(full_witness);

        // Compute weights from R1CS matrices
        let alphas = calculate_external_row_of_r1cs_matrices(alpha, r1cs);
        let public_weight = get_public_weights(public_inputs, &mut merlin, self.m);

        if is_single {
            // Single commitment path
            let commitment = commitments.into_iter().next().unwrap();
            let alphas: [Vec<FieldElement>; 3] = alphas.try_into().unwrap();

            let (mut statement, f_sums, g_sums) = create_combined_statement_over_two_polynomials::<3>(
                self.m,
                &commitment.commitment_to_witness,
                &commitment.masked_polynomial,
                &commitment.random_polynomial,
                &alphas,
            );

            merlin.hint::<(Vec<FieldElement>, Vec<FieldElement>)>(&(f_sums, g_sums))?;

            let (public_f_sum, public_g_sum) = if public_inputs.is_empty() {
                // If there are no public inputs, the hint is unused by the verifier and can be
                // assigned an arbitrary value.
                let public_f_sum = FieldElement::zero();
                let public_g_sum = FieldElement::zero();
                (public_f_sum, public_g_sum)
            } else {
                update_statement_with_public_weights(
                    &mut statement,
                    &commitment.commitment_to_witness,
                    &commitment.masked_polynomial,
                    &commitment.random_polynomial,
                    public_weight,
                )
            };

            merlin.hint::<(FieldElement, FieldElement)>(&(public_f_sum, public_g_sum))?;

            run_zk_whir_pcs_prover(
                commitment.commitment_to_witness,
                statement,
                &self.whir_witness,
                &mut merlin,
            );
        } else {
            // Dual commitment path
            let mut commitments = commitments.into_iter();
            let c1 = commitments.next().unwrap();
            let c2 = commitments.next().unwrap();

            // Split alphas between w1 and w2
            let (alphas_1, alphas_2): (Vec<_>, Vec<_>) = alphas
                .into_iter()
                .map(|mut v| {
                    let v2 = v.split_off(self.w1_size);
                    (v, v2)
                })
                .unzip();

            let alphas_1: [Vec<FieldElement>; 3] = alphas_1.try_into().unwrap();
            let alphas_2: [Vec<FieldElement>; 3] = alphas_2.try_into().unwrap();

            let (mut statement_1, f_sums_1, g_sums_1) =
                create_combined_statement_over_two_polynomials::<3>(
                    self.m,
                    &c1.commitment_to_witness,
                    &c1.masked_polynomial,
                    &c1.random_polynomial,
                    &alphas_1,
                );
            drop(alphas_1);

            let (statement_2, f_sums_2, g_sums_2) =
                create_combined_statement_over_two_polynomials::<3>(
                    self.m,
                    &c2.commitment_to_witness,
                    &c2.masked_polynomial,
                    &c2.random_polynomial,
                    &alphas_2,
                );
            drop(alphas_2);

            merlin.hint::<(Vec<FieldElement>, Vec<FieldElement>)>(&(f_sums_1, g_sums_1))?;
            merlin.hint::<(Vec<FieldElement>, Vec<FieldElement>)>(&(f_sums_2, g_sums_2))?;

            let (public_f_sum, public_g_sum) = if public_inputs.is_empty() {
                let public_f_sum = FieldElement::zero();
                let public_g_sum = FieldElement::zero();
                (public_f_sum, public_g_sum)
            } else {
                update_statement_with_public_weights(
                    &mut statement_1,
                    &c1.commitment_to_witness,
                    &c1.masked_polynomial,
                    &c1.random_polynomial,
                    public_weight,
                )
            };

            merlin.hint::<(FieldElement, FieldElement)>(&(public_f_sum, public_g_sum))?;

            run_zk_whir_pcs_batch_prover(
                &[c1.commitment_to_witness, c2.commitment_to_witness],
                &[statement_1, statement_2],
                &self.whir_witness,
                &mut merlin,
            );
        }

        Ok(WhirR1CSProof {
            transcript: merlin.narg_string().to_vec(),
        })
    }
}

pub fn compute_blinding_coefficients_for_round(
    g_univariates: &[[FieldElement; 4]],
    compute_for: usize,
    alphas: &[FieldElement],
) -> [FieldElement; 4] {
    let mut compute_for = compute_for;
    let n = g_univariates.len();
    assert!(compute_for <= n);
    assert_eq!(alphas.len(), compute_for);
    let mut all_fixed = false;
    if compute_for == n {
        all_fixed = true;
        compute_for = n - 1;
    }

    // p = Σ_{i<r} g_i(α_i)
    let mut prefix_sum = FieldElement::zero();
    for i in 0..compute_for {
        prefix_sum += eval_cubic_poly(g_univariates[i], alphas[i]);
    }

    // s = Σ_{i>r}(g_i(0) + g_i(1))
    let mut suffix_sum = FieldElement::zero();
    for g_coeffs in g_univariates.iter().skip(compute_for + 1) {
        suffix_sum += eval_cubic_poly(*g_coeffs, FieldElement::zero())
            + eval_cubic_poly(*g_coeffs, FieldElement::one());
    }

    let two = FieldElement::one() + FieldElement::one();
    let mut prefix_multiplier = FieldElement::one();
    for _ in 0..(n - 1 - compute_for) {
        prefix_multiplier = prefix_multiplier + prefix_multiplier;
    }
    let suffix_multiplier = prefix_multiplier / two;

    let constant_term_from_other_items =
        prefix_multiplier * prefix_sum + suffix_multiplier * suffix_sum;

    let coefficient_for_current_index = &g_univariates[compute_for];

    if all_fixed {
        let value = eval_cubic_poly(
            [
                prefix_multiplier * coefficient_for_current_index[0]
                    + constant_term_from_other_items,
                prefix_multiplier * coefficient_for_current_index[1],
                prefix_multiplier * coefficient_for_current_index[2],
                prefix_multiplier * coefficient_for_current_index[3],
            ],
            alphas[compute_for],
        );
        return [
            value,
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
        ];
    }

    [
        prefix_multiplier * coefficient_for_current_index[0] + constant_term_from_other_items,
        prefix_multiplier * coefficient_for_current_index[1],
        prefix_multiplier * coefficient_for_current_index[2],
        prefix_multiplier * coefficient_for_current_index[3],
    ]
}

pub fn sum_over_hypercube(g_univariates: &[[FieldElement; 4]]) -> FieldElement {
    let fixed_variables: &[FieldElement] = &[];
    let polynomial_coefficient =
        compute_blinding_coefficients_for_round(g_univariates, 0, fixed_variables);

    eval_cubic_poly(polynomial_coefficient, FieldElement::zero())
        + eval_cubic_poly(polynomial_coefficient, FieldElement::one())
}

pub fn batch_commit_to_polynomial(
    m: usize,
    whir_config: &WhirConfig,
    witness: EvaluationsList<FieldElement>,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
) -> (
    Witness<FieldElement, SkyscraperMerkleConfig>,
    EvaluationsList<FieldElement>,
    EvaluationsList<FieldElement>,
) {
    let mask = generate_random_multilinear_polynomial(witness.num_variables());
    let masked_polynomial_coeff = create_masked_polynomial(witness, &mask).to_coeffs();
    drop(mask);

    let random_polynomial_coeff =
        EvaluationsList::new(generate_random_multilinear_polynomial(m)).to_coeffs();

    let committer = CommitmentWriter::new(whir_config.clone());
    let witness_new = committer
        .commit_batch(merlin, &[
            &masked_polynomial_coeff,
            &random_polynomial_coeff,
        ])
        .expect("WHIR prover failed to commit");

    (
        witness_new,
        masked_polynomial_coeff.into(),
        random_polynomial_coeff.into(),
    )
}

fn generate_blinding_spartan_univariate_polys(m_0: usize) -> Vec<[FieldElement; 4]> {
    let mut rng = ark_std::rand::thread_rng();
    let mut g_univariates = Vec::with_capacity(m_0);

    for _ in 0..m_0 {
        let coeffs: [FieldElement; 4] = [
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
            FieldElement::rand(&mut rng),
        ];
        g_univariates.push(coeffs);
    }
    g_univariates
}

/// Pads `v` with zeros so that `len >= 2` and `len` is a power of two.
#[inline]
pub fn pad_to_pow2_len_min2(v: &mut Vec<FieldElement>) {
    let min = v.len().max(2);

    let target = match min.checked_next_power_of_two() {
        Some(p2) => p2,
        None => min, // fallback: can't grow to power-of-two, keep `min`
    };

    if v.len() < target {
        v.resize(target, FieldElement::zero());
    }
}

#[instrument(skip_all)]
pub fn run_zk_sumcheck_prover(
    r1cs: &R1CS,
    z: &[FieldElement],
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    m_0: usize,
    whir_for_blinding_of_spartan_config: &WhirConfig,
) -> Vec<FieldElement> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    merlin
        .fill_challenge_scalars(&mut r)
        .expect("Failed to extract challenge scalars from Merlin");
    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    let ((mut a, mut b, mut c), mut eq) = rayon::join(
        || calculate_witness_bounds(r1cs, z),
        || calculate_evaluations_over_boolean_hypercube_for_eq(r),
    );

    // Ensure each vector has length ≥2 and is a power of two.
    pad_to_pow2_len_min2(&mut a);
    pad_to_pow2_len_min2(&mut b);
    pad_to_pow2_len_min2(&mut c);
    pad_to_pow2_len_min2(&mut eq);

    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);

    let blinding_polynomial = generate_blinding_spartan_univariate_polys(m_0);

    // Spartan blinding: m = log2(domain), target_len = 2^(m-1).
    let blinding_num_vars = whir_for_blinding_of_spartan_config
        .mv_parameters
        .num_variables;
    let target_b = 1usize << (blinding_num_vars - 1);

    //  Flatten and pad to exactly 1 << blinding_num_vars - 1
    let mut flat = blinding_polynomial
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    if flat.len() < target_b {
        flat.resize(target_b, FieldElement::zero());
    }

    let blinding_polynomial_for_committing = EvaluationsList::new(flat);
    let blinding_polynomial_variables = blinding_polynomial_for_committing.num_variables();
    let (commitment_to_blinding_polynomial, blindings_mask_polynomial, blindings_blind_polynomial) =
        batch_commit_to_polynomial(
            blinding_polynomial_variables + 1,
            whir_for_blinding_of_spartan_config,
            blinding_polynomial_for_committing,
            merlin,
        );

    let sum_g_reduce = sum_over_hypercube(&blinding_polynomial);

    let _ = merlin.add_scalars(&[sum_g_reduce]);

    let mut rho_buf = [FieldElement::zero()];
    let _ = merlin.fill_challenge_scalars(&mut rho_buf);
    let rho = rho_buf[0];

    // Instead of proving that sum of F over the boolean hypercube is 0, we prove
    // that sum of F + rho * G over the boolean hypercube is rho * Sum G.
    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_reduce;

    let mut fold = None;

    for idx in 0..m_0 {
        // Here hhat_i_at_x represents hhat_i(x). hhat_i(x) is the qubic sumcheck
        // polynomial sent by the prover.
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut a, &mut b, &mut c, &mut eq], fold, |[a, b, c, eq]| {
                let f0 = eq.0 * (a.0 * b.0 - c.0);
                let f_em1 = (eq.0 + eq.0 - eq.1)
                    * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
                let f_inf = (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);

                [f0, f_em1, f_inf]
            });
        if fold.is_some() {
            a.truncate(a.len() / 2);
            b.truncate(b.len() / 2);
            c.truncate(c.len() / 2);
            eq.truncate(eq.len() / 2);
        }

        let g_poly = compute_blinding_coefficients_for_round(
            blinding_polynomial.as_slice(),
            idx,
            alpha.as_slice(),
        );

        let mut combined_hhat_i_coeffs = [FieldElement::zero(); 4];

        combined_hhat_i_coeffs[0] = hhat_i_at_0 + rho * g_poly[0];

        let g_at_minus_one = g_poly[0] - g_poly[1] + g_poly[2] - g_poly[3];
        let combined_at_em1 = hhat_i_at_em1 + rho * g_at_minus_one;

        combined_hhat_i_coeffs[2] = HALF
            * (saved_val_for_sumcheck_equality_assertion + combined_at_em1
                - combined_hhat_i_coeffs[0]
                - combined_hhat_i_coeffs[0]
                - combined_hhat_i_coeffs[0]);

        combined_hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube + rho * g_poly[3];

        combined_hhat_i_coeffs[1] = saved_val_for_sumcheck_equality_assertion
            - combined_hhat_i_coeffs[0]
            - combined_hhat_i_coeffs[0]
            - combined_hhat_i_coeffs[3]
            - combined_hhat_i_coeffs[2];

        assert_eq!(
            saved_val_for_sumcheck_equality_assertion,
            combined_hhat_i_coeffs[0]
                + combined_hhat_i_coeffs[0]
                + combined_hhat_i_coeffs[1]
                + combined_hhat_i_coeffs[2]
                + combined_hhat_i_coeffs[3]
        );

        let _ = merlin.add_scalars(&combined_hhat_i_coeffs[..]);
        let mut alpha_i_wrapped_in_vector = [FieldElement::zero()];
        let _ = merlin.fill_challenge_scalars(&mut alpha_i_wrapped_in_vector);
        let alpha_i = alpha_i_wrapped_in_vector[0];
        alpha.push(alpha_i);

        fold = Some(alpha_i);

        saved_val_for_sumcheck_equality_assertion =
            eval_cubic_poly(combined_hhat_i_coeffs, alpha_i);
    }
    drop((a, b, c, eq));

    let (statement, blinding_mask_polynomial_sum, blinding_blind_polynomial_sum) =
        create_combined_statement_over_two_polynomials::<1>(
            blinding_polynomial_variables + 1,
            &commitment_to_blinding_polynomial,
            &blindings_mask_polynomial,
            &blindings_blind_polynomial,
            &[expand_powers(alpha.as_slice())],
        );

    let _ = merlin.add_scalars(&[
        blinding_mask_polynomial_sum[0],
        blinding_blind_polynomial_sum[0],
    ]);

    let (_sums, _deferred) = run_zk_whir_pcs_prover(
        commitment_to_blinding_polynomial,
        statement,
        &whir_for_blinding_of_spartan_config,
        merlin,
    );

    alpha
}

fn expand_powers(values: &[FieldElement]) -> Vec<FieldElement> {
    let mut result = Vec::with_capacity(values.len() * 4);
    for &value in values {
        result.push(FieldElement::one());
        result.push(value);
        result.push(value * value);
        result.push(value * value * value);
    }
    result
}

fn create_combined_statement_over_two_polynomials<const N: usize>(
    cfg_nv: usize,
    witness: &Witness<FieldElement, SkyscraperMerkleConfig>,
    f_polynomial: &EvaluationsList<FieldElement>,
    g_polynomial: &EvaluationsList<FieldElement>,
    alphas: &[Vec<FieldElement>; N],
) -> (
    Statement<FieldElement>,
    Vec<FieldElement>,
    Vec<FieldElement>,
) {
    // base_nv = cfg_nv - 1; lengths: 2^(cfg_nv-1) and 2^cfg_nv.
    let base_nv = cfg_nv.checked_sub(1).expect("cfg_nv >= 1");
    let base_len = 1usize << base_nv;
    let final_len = 1usize << cfg_nv;

    let mut statement = Statement::<FieldElement>::new(cfg_nv);
    let mut f_sums = Vec::with_capacity(N);
    let mut g_sums = Vec::with_capacity(N);

    for w in alphas.into_iter() {
        // lift to 2^{cfg_nv} by zeroing the mask half: [w || 0]
        let mut w_full = Vec::with_capacity(final_len);
        w_full.extend_from_slice(w);

        // Ensure w has length base_len (pad if shorter, assert if longer)
        if w_full.len() < base_len {
            w_full.resize(base_len, FieldElement::zero());
        } else {
            assert_eq!(w_full.len(), base_len);
        }
        w_full.resize(final_len, FieldElement::zero());

        let weight = Weights::linear(EvaluationsList::new(w_full));
        let f = weight.weighted_sum(f_polynomial);
        let g = weight.weighted_sum(g_polynomial);

        statement.add_constraint(weight, f + witness.batching_randomness * g);
        f_sums.push(f);
        g_sums.push(g);
    }

    (statement, f_sums, g_sums)
}

#[instrument(skip_all)]
pub fn run_zk_whir_pcs_prover(
    witnesses: Witness<FieldElement, SkyscraperMerkleConfig>,
    statements: Statement<FieldElement>,
    params: &WhirConfig,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
) -> (MultilinearPoint<FieldElement>, Vec<FieldElement>) {
    info!("WHIR Parameters: {params}");

    if !params.check_pow_bits() {
        warn!("More PoW bits required than specified.");
    }

    let prover = Prover::new(params.clone());
    let (randomness, deferred) = prover
        .prove(merlin, statements, witnesses)
        .expect("WHIR prover failed to generate a proof");

    (randomness, deferred)
}

#[instrument(skip_all)]
pub fn run_zk_whir_pcs_batch_prover(
    witnesses: &[Witness<FieldElement, SkyscraperMerkleConfig>],
    statements: &[Statement<FieldElement>],
    params: &WhirConfig,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
) -> (MultilinearPoint<FieldElement>, Vec<FieldElement>) {
    info!("WHIR Parameters: {params}");

    if !params.check_pow_bits() {
        warn!("More PoW bits required than specified.");
    }

    let prover = Prover::new(params.clone());
    let (randomness, deferred) = prover
        .prove_batch(merlin, statements, witnesses)
        .expect("WHIR prover failed to generate a proof");

    (randomness, deferred)
}

fn update_statement_with_public_weights(
    statement: &mut Statement<FieldElement>,
    witness: &Witness<FieldElement, SkyscraperMerkleConfig>,
    f_polynomial: &EvaluationsList<FieldElement>,
    g_polynomial: &EvaluationsList<FieldElement>,
    public_weights: Weights<FieldElement>,
) -> (FieldElement, FieldElement) {
    let f = public_weights.weighted_sum(f_polynomial);
    let g = public_weights.weighted_sum(g_polynomial);
    statement.add_constraint_in_front(public_weights, f + witness.batching_randomness * g);
    (f, g)
}

fn get_public_weights(
    public_inputs: &PublicInputs,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    m: usize,
) -> Weights<FieldElement> {
    // Add hash to transcript
    let public_inputs_hash = public_inputs.hash();
    let _ = merlin.add_scalars(&[public_inputs_hash]);

    // Get random point x
    let mut x_buf = [FieldElement::zero()];
    merlin
        .fill_challenge_scalars(&mut x_buf)
        .expect("Failed to get challenge from Merlin");
    let x = x_buf[0];

    let domain_size = 1 << m;
    let mut public_weights = vec![FieldElement::zero(); domain_size];

    // Set public weights for public inputs [1,x,x^2,x^3...x^n-1,0,0,0...0]
    let mut current_pow = FieldElement::one();
    for (idx, _) in public_inputs.0.iter().enumerate() {
        public_weights[idx] = current_pow;
        current_pow = current_pow * x;
    }

    Weights::geometric(
        x,
        public_inputs.0.len(),
        EvaluationsList::new(public_weights),
    )
}
