use {
    anyhow::{ensure, Result},
    ark_ff::UniformRand,
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
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
    std::mem,
    tracing::{debug, instrument},
    whir::{
        algebra::{
            dot,
            embedding::Basefield,
            ntt::wavelet_transform,
            polynomials::{CoefficientList, EvaluationsList, MultilinearPoint},
            weights::{Covector, Evaluate},
        },
        protocols::whir::Witness,
        transcript::{ProverState, VerifierMessage},
    },
};

/// Transform coefficients to evaluation form once, reusable across multiple
/// weight dot products. Avoids the per-call clone+transform inside
/// `Covector::evaluate`.
fn coeffs_to_evals(poly: &CoefficientList<FieldElement>) -> Vec<FieldElement> {
    let mut evals = poly.coeffs().to_vec();
    wavelet_transform(&mut evals);
    evals
}

/// Dot product of a covector's weight vector against pre-transformed
/// evaluations.
fn covector_dot(w: &Covector<FieldElement>, evals: &[FieldElement]) -> FieldElement {
    dot(&w.vector, evals)
}

pub struct WhirR1CSCommitment {
    pub commitment_to_witness:   Witness<FieldElement>,
    pub masked_polynomial_coeff: CoefficientList<FieldElement>,
    pub random_polynomial_coeff: CoefficientList<FieldElement>,
    pub padded_witness:          Vec<FieldElement>,
}

pub trait WhirR1CSProver {
    fn commit(
        &self,
        merlin: &mut ProverState<SkyscraperSponge>,
        r1cs: &R1CS,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment>;

    fn prove(
        &self,
        merlin: ProverState<SkyscraperSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof>;
}

impl WhirR1CSProver for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn commit(
        &self,
        merlin: &mut ProverState<SkyscraperSponge>,
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
        let whir_num_vars = self.whir_witness.initial_num_variables();

        // Expected evaluation length = 2^(log2(domain) - 1).
        let target_len = 1usize << (whir_num_vars - 1);

        // Pad witness to power-of-two, then extend to target_len with zeros.
        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < target_len {
            padded_witness.resize(target_len, FieldElement::zero());
        }

        let witness_polynomial_evals = EvaluationsList::new(padded_witness.clone());

        let (commitment_to_witness, masked_polynomial_coeff, random_polynomial_coeff) =
            batch_commit_to_polynomial(
                self.m,
                &self.whir_witness,
                witness_polynomial_evals,
                merlin,
            );

        Ok(WhirR1CSCommitment {
            commitment_to_witness,
            masked_polynomial_coeff,
            random_polynomial_coeff,
            padded_witness,
        })
    }

    #[instrument(skip_all)]
    fn prove(
        &self,
        mut merlin: ProverState<SkyscraperSponge>,
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
            let (mut weights, f_sums, g_sums) =
                create_weights_and_evaluations_for_two_polynomials::<3>(
                    self.m,
                    &commitment.masked_polynomial_coeff,
                    &commitment.random_polynomial_coeff,
                    &alphas,
                );

            merlin.prover_hint_ark(&(f_sums, g_sums));

            let (public_f_sum, public_g_sum) = if public_inputs.is_empty() {
                (FieldElement::zero(), FieldElement::zero())
            } else {
                compute_public_weight_evaluations(
                    &mut weights,
                    &commitment.masked_polynomial_coeff,
                    &commitment.random_polynomial_coeff,
                    public_weight,
                )
            };

            merlin.prover_hint_ark(&(public_f_sum, public_g_sum));

            // Build evaluations: for each weight, eval on masked + eval on random
            let evaluations = compute_evaluations_single(
                &weights,
                &commitment.masked_polynomial_coeff,
                &commitment.random_polynomial_coeff,
            );

            let weight_refs: Vec<&dyn Evaluate<Basefield<FieldElement>>> = weights
                .iter()
                .map(|w| w as &dyn Evaluate<Basefield<FieldElement>>)
                .collect();

            run_zk_whir_pcs_prover(
                &[&commitment.commitment_to_witness],
                &[
                    &commitment.masked_polynomial_coeff,
                    &commitment.random_polynomial_coeff,
                ],
                &weight_refs,
                &evaluations,
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

            let (mut weights_1, f_sums_1, g_sums_1) =
                create_weights_and_evaluations_for_two_polynomials::<3>(
                    self.m,
                    &c1.masked_polynomial_coeff,
                    &c1.random_polynomial_coeff,
                    &alphas_1,
                );
            drop(alphas_1);

            let (weights_2, f_sums_2, g_sums_2) =
                create_weights_and_evaluations_for_two_polynomials::<3>(
                    self.m,
                    &c2.masked_polynomial_coeff,
                    &c2.random_polynomial_coeff,
                    &alphas_2,
                );
            drop(alphas_2);

            // Compute cross-evaluations: weights_1 on c2's polynomials and
            // weights_2 on c1's polynomials. Whir's prove() expects evaluations
            // for ALL (weight, polynomial) pairs in row-major order.
            let c1m_evals = coeffs_to_evals(&c1.masked_polynomial_coeff);
            let c1r_evals = coeffs_to_evals(&c1.random_polynomial_coeff);
            let c2m_evals = coeffs_to_evals(&c2.masked_polynomial_coeff);
            let c2r_evals = coeffs_to_evals(&c2.random_polynomial_coeff);
            let cross_f_12: Vec<FieldElement> = weights_1
                .iter()
                .map(|w| covector_dot(w, &c2m_evals))
                .collect();
            let cross_g_12: Vec<FieldElement> = weights_1
                .iter()
                .map(|w| covector_dot(w, &c2r_evals))
                .collect();
            let cross_f_21: Vec<FieldElement> = weights_2
                .iter()
                .map(|w| covector_dot(w, &c1m_evals))
                .collect();
            let cross_g_21: Vec<FieldElement> = weights_2
                .iter()
                .map(|w| covector_dot(w, &c1r_evals))
                .collect();

            merlin.prover_hint_ark(&(f_sums_1.clone(), g_sums_1.clone()));
            merlin.prover_hint_ark(&(f_sums_2.clone(), g_sums_2.clone()));
            merlin.prover_hint_ark(&(cross_f_12.clone(), cross_g_12.clone()));
            merlin.prover_hint_ark(&(cross_f_21.clone(), cross_g_21.clone()));

            let (public_f1, public_g1, public_f2, public_g2) = if public_inputs.is_empty() {
                (
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                    FieldElement::zero(),
                )
            } else {
                compute_public_weight_evaluations_dual(
                    &mut weights_1,
                    &c1.masked_polynomial_coeff,
                    &c1.random_polynomial_coeff,
                    &c2.masked_polynomial_coeff,
                    &c2.random_polynomial_coeff,
                    public_weight,
                )
            };

            merlin.prover_hint_ark(&(public_f1, public_g1, public_f2, public_g2));

            // Combine weights from both commitments
            let mut all_weights = weights_1;
            all_weights.extend(weights_2);

            // Build evaluations: for each weight, evaluate on all 4 polynomials
            // (c1_masked, c1_random, c2_masked, c2_random)
            // This is row-major: evaluations[w_idx * 4 + p_idx]
            let all_polys: Vec<&CoefficientList<FieldElement>> = vec![
                &c1.masked_polynomial_coeff,
                &c1.random_polynomial_coeff,
                &c2.masked_polynomial_coeff,
                &c2.random_polynomial_coeff,
            ];

            let poly_evals: Vec<Vec<FieldElement>> =
                all_polys.iter().map(|p| coeffs_to_evals(p)).collect();
            let evaluations: Vec<FieldElement> = all_weights
                .iter()
                .flat_map(|w| poly_evals.iter().map(|pe| covector_dot(w, pe)))
                .collect();

            let weight_refs: Vec<&dyn Evaluate<Basefield<FieldElement>>> = all_weights
                .iter()
                .map(|w| w as &dyn Evaluate<Basefield<FieldElement>>)
                .collect();

            run_zk_whir_pcs_prover(
                &[&c1.commitment_to_witness, &c2.commitment_to_witness],
                &all_polys,
                &weight_refs,
                &evaluations,
                &self.whir_witness,
                &mut merlin,
            );
        }

        let proof = merlin.proof();
        Ok(WhirR1CSProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
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
    merlin: &mut ProverState<SkyscraperSponge>,
) -> (
    Witness<FieldElement>,
    CoefficientList<FieldElement>,
    CoefficientList<FieldElement>,
) {
    let mask = generate_random_multilinear_polynomial(witness.num_variables());
    let masked_polynomial_coeff = create_masked_polynomial(witness, &mask).to_coeffs();
    drop(mask);

    let random_polynomial_coeff =
        EvaluationsList::new(generate_random_multilinear_polynomial(m)).to_coeffs();

    let witness_new = whir_config.commit(merlin, &[
        &masked_polynomial_coeff,
        &random_polynomial_coeff,
    ]);

    (
        witness_new,
        masked_polynomial_coeff,
        random_polynomial_coeff,
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
    merlin: &mut ProverState<SkyscraperSponge>,
    m_0: usize,
    whir_for_blinding_of_spartan_config: &WhirConfig,
) -> Vec<FieldElement> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let r: Vec<FieldElement> = merlin.verifier_message_vec(m_0);
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
    let blinding_num_vars = whir_for_blinding_of_spartan_config.initial_num_variables();
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

    merlin.prover_message(&sum_g_reduce);

    let rho: FieldElement = merlin.verifier_message();

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

        for coeff in &combined_hhat_i_coeffs {
            merlin.prover_message(coeff);
        }
        let alpha_i: FieldElement = merlin.verifier_message();
        alpha.push(alpha_i);

        fold = Some(alpha_i);

        saved_val_for_sumcheck_equality_assertion =
            eval_cubic_poly(combined_hhat_i_coeffs, alpha_i);
    }
    drop((a, b, c, eq));

    let (blinding_weights, blinding_mask_polynomial_sum, blinding_blind_polynomial_sum) =
        create_weights_and_evaluations_for_two_polynomials::<1>(
            blinding_polynomial_variables + 1,
            &blindings_mask_polynomial,
            &blindings_blind_polynomial,
            &[expand_powers(alpha.as_slice())],
        );

    merlin.prover_message(&blinding_mask_polynomial_sum[0]);
    merlin.prover_message(&blinding_blind_polynomial_sum[0]);

    let blinding_evaluations = compute_evaluations_single(
        &blinding_weights,
        &blindings_mask_polynomial,
        &blindings_blind_polynomial,
    );

    let blinding_weight_refs: Vec<&dyn Evaluate<Basefield<FieldElement>>> = blinding_weights
        .iter()
        .map(|w| w as &dyn Evaluate<Basefield<FieldElement>>)
        .collect();

    let (_sums, _deferred) = run_zk_whir_pcs_prover(
        &[&commitment_to_blinding_polynomial],
        &[&blindings_mask_polynomial, &blindings_blind_polynomial],
        &blinding_weight_refs,
        &blinding_evaluations,
        whir_for_blinding_of_spartan_config,
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

fn create_weights_and_evaluations_for_two_polynomials<const N: usize>(
    cfg_nv: usize,
    f_polynomial: &CoefficientList<FieldElement>,
    g_polynomial: &CoefficientList<FieldElement>,
    alphas: &[Vec<FieldElement>; N],
) -> (
    Vec<Covector<FieldElement>>,
    Vec<FieldElement>,
    Vec<FieldElement>,
) {
    let base_nv = cfg_nv.checked_sub(1).expect("cfg_nv >= 1");
    let base_len = 1usize << base_nv;
    let final_len = 1usize << cfg_nv;

    let f_evals = coeffs_to_evals(f_polynomial);
    let g_evals = coeffs_to_evals(g_polynomial);

    let mut weights = Vec::with_capacity(N);
    let mut f_sums = Vec::with_capacity(N);
    let mut g_sums = Vec::with_capacity(N);

    for w in alphas.iter() {
        let mut w_full = Vec::with_capacity(final_len);
        w_full.extend_from_slice(w);

        if w_full.len() < base_len {
            w_full.resize(base_len, FieldElement::zero());
        } else {
            assert_eq!(w_full.len(), base_len);
        }
        w_full.resize(final_len, FieldElement::zero());

        let weight = Covector::new(w_full);
        f_sums.push(covector_dot(&weight, &f_evals));
        g_sums.push(covector_dot(&weight, &g_evals));

        weights.push(weight);
    }

    (weights, f_sums, g_sums)
}

fn compute_evaluations_single(
    weights: &[Covector<FieldElement>],
    masked_poly: &CoefficientList<FieldElement>,
    random_poly: &CoefficientList<FieldElement>,
) -> Vec<FieldElement> {
    let masked_evals = coeffs_to_evals(masked_poly);
    let random_evals = coeffs_to_evals(random_poly);
    weights
        .iter()
        .flat_map(|w| {
            [
                covector_dot(w, &masked_evals),
                covector_dot(w, &random_evals),
            ]
        })
        .collect()
}

#[instrument(skip_all)]
pub fn run_zk_whir_pcs_prover(
    witnesses: &[&Witness<FieldElement>],
    polynomials: &[&CoefficientList<FieldElement>],
    weights: &[&dyn Evaluate<Basefield<FieldElement>>],
    evaluations: &[FieldElement],
    params: &WhirConfig,
    merlin: &mut ProverState<SkyscraperSponge>,
) -> (MultilinearPoint<FieldElement>, Vec<FieldElement>) {
    debug!("WHIR Parameters: {params}");

    let (randomness, deferred) = params.prove(merlin, polynomials, witnesses, weights, evaluations);

    (randomness, deferred)
}

fn compute_public_weight_evaluations(
    weights: &mut Vec<Covector<FieldElement>>,
    f_polynomial: &CoefficientList<FieldElement>,
    g_polynomial: &CoefficientList<FieldElement>,
    public_weights: Covector<FieldElement>,
) -> (FieldElement, FieldElement) {
    let f_evals = coeffs_to_evals(f_polynomial);
    let g_evals = coeffs_to_evals(g_polynomial);
    let f = covector_dot(&public_weights, &f_evals);
    let g = covector_dot(&public_weights, &g_evals);
    weights.insert(0, public_weights);
    (f, g)
}

fn compute_public_weight_evaluations_dual(
    weights_1: &mut Vec<Covector<FieldElement>>,
    c1_masked: &CoefficientList<FieldElement>,
    c1_random: &CoefficientList<FieldElement>,
    c2_masked: &CoefficientList<FieldElement>,
    c2_random: &CoefficientList<FieldElement>,
    public_weights: Covector<FieldElement>,
) -> (FieldElement, FieldElement, FieldElement, FieldElement) {
    let c1m = coeffs_to_evals(c1_masked);
    let c1r = coeffs_to_evals(c1_random);
    let c2m = coeffs_to_evals(c2_masked);
    let c2r = coeffs_to_evals(c2_random);
    let f1 = covector_dot(&public_weights, &c1m);
    let g1 = covector_dot(&public_weights, &c1r);
    let f2 = covector_dot(&public_weights, &c2m);
    let g2 = covector_dot(&public_weights, &c2r);
    weights_1.insert(0, public_weights);
    (f1, g1, f2, g2)
}

fn get_public_weights(
    public_inputs: &PublicInputs,
    merlin: &mut ProverState<SkyscraperSponge>,
    m: usize,
) -> Covector<FieldElement> {
    let public_inputs_hash = public_inputs.hash();
    merlin.prover_message(&public_inputs_hash);

    let x: FieldElement = merlin.verifier_message();

    let domain_size = 1 << m;
    let mut public_weights = vec![FieldElement::zero(); domain_size];

    let mut current_pow = FieldElement::one();
    for slot in public_weights.iter_mut().take(public_inputs.len()) {
        *slot = current_pow;
        current_pow *= x;
    }

    let mut covector = Covector::new(public_weights);
    covector.deferred = false;
    covector
}
