use {
    anyhow::{ensure, Result},
    ark_ff::UniformRand,
    ark_std::{One, Zero},
    provekit_common::{
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
        FieldElement, PublicInputs, TranscriptSponge, WhirConfig, WhirR1CSProof, WhirR1CSScheme,
        R1CS,
    },
    rayon::prelude::*,
    std::{any::Any, borrow::Cow},
    tracing::{debug, instrument},
    whir::{
        algebra::{
            dot, embedding::Basefield, linear_form::LinearForm, multilinear_extend,
            MultilinearPoint,
        },
        protocols::whir::Witness,
        transcript::{ProverState, VerifierMessage},
    },
};

type WhirWitness = Witness<FieldElement, Basefield<FieldElement>>;

pub struct WhirR1CSCommitment {
    pub commitment_to_witness: WhirWitness,
    pub masked_polynomial:     Vec<FieldElement>,
    pub random_polynomial:     Vec<FieldElement>,
}

/// A covector that stores only a power-of-two prefix, with the rest
/// implicitly zero-padded to `logical_size`. Saves memory when the
/// covector is known to be zero beyond the prefix (e.g. R1CS alpha
/// weights that are zero-padded from 2^(m-1) to 2^m).
///
/// Implements [`LinearForm`] so it can be passed directly to whir's
/// `prove()` in place of a full-length `Covector`.
struct PrefixCovector {
    /// The non-zero prefix. Length must be a power of two.
    vector:       Vec<FieldElement>,
    /// The full logical domain size (also a power of two, ≥ vector.len()).
    logical_size: usize,
    deferred:     bool,
}

impl PrefixCovector {
    /// Create a prefix covector with `deferred = true` (the default for
    /// R1CS alpha weights whose MLE the caller verifies externally).
    fn new(vector: Vec<FieldElement>, logical_size: usize) -> Self {
        debug_assert!(vector.len().is_power_of_two());
        debug_assert!(logical_size.is_power_of_two());
        debug_assert!(logical_size >= vector.len());
        Self {
            vector,
            logical_size,
            deferred: true,
        }
    }
}

impl LinearForm<FieldElement> for PrefixCovector {
    fn size(&self) -> usize {
        self.logical_size
    }

    fn deferred(&self) -> bool {
        self.deferred
    }

    fn mle_evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let k = self.vector.len().trailing_zeros() as usize;
        // The prefix occupies indices 0..2^k (the lower half of each
        // successive doubling). In whir's big-endian variable ordering,
        // the first variable selects the upper/lower half of the array.
        // So the r = len - k leading variables must all be 0 for the
        // prefix region, contributing a factor of ∏(1 − pⱼ) for j < r.
        let r = point.len() - k;
        let head_factor: FieldElement =
            point[..r].iter().map(|p| FieldElement::one() - p).product();
        let prefix_mle = multilinear_extend(&self.vector, &point[r..]);
        head_factor * prefix_mle
    }

    fn accumulate(&self, accumulator: &mut [FieldElement], scalar: FieldElement) {
        debug_assert!(
            accumulator.len() >= self.vector.len(),
            "accumulator too short for PrefixCovector: {} < {}",
            accumulator.len(),
            self.vector.len()
        );
        for (acc, val) in accumulator[..self.vector.len()]
            .iter_mut()
            .zip(&self.vector)
        {
            *acc += scalar * *val;
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait WhirR1CSProver {
    fn commit(
        &self,
        merlin: &mut ProverState<TranscriptSponge>,
        num_witnesses: usize,
        num_constraints: usize,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment>;

    fn prove(
        &self,
        merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        full_witness: Vec<FieldElement>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof>;
}

impl WhirR1CSProver for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn commit(
        &self,
        merlin: &mut ProverState<TranscriptSponge>,
        num_witnesses: usize,
        num_constraints: usize,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment> {
        let witness_size = if is_w1 {
            self.w1_size
        } else {
            num_witnesses - self.w1_size
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
            num_constraints <= 1 << self.m_0,
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

        let (commitment_to_witness, masked_polynomial, random_polynomial) =
            batch_commit_to_polynomial(self.m, &self.whir_witness, padded_witness, merlin);

        Ok(WhirR1CSCommitment {
            commitment_to_witness,
            masked_polynomial,
            random_polynomial,
        })
    }

    #[instrument(skip_all)]
    fn prove(
        &self,
        mut merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        full_witness: Vec<FieldElement>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        let is_single = commitments.len() == 1;

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
                    &commitment.masked_polynomial,
                    &commitment.random_polynomial,
                    alphas,
                );

            merlin.prover_hint_ark(&(f_sums, g_sums));

            let (public_f_sum, public_g_sum) = if public_inputs.is_empty() {
                // If there are no public inputs, the hint is unused by the verifier
                // and can be assigned an arbitrary value.
                (FieldElement::zero(), FieldElement::zero())
            } else {
                compute_public_weight_evaluations(
                    &mut weights,
                    &commitment.masked_polynomial,
                    &commitment.random_polynomial,
                    public_weight,
                )
            };

            merlin.prover_hint_ark(&(public_f_sum, public_g_sum));

            // Build evaluations: for each weight, eval on masked + eval on random
            let evaluations = compute_evaluations_single(
                &weights,
                &commitment.masked_polynomial,
                &commitment.random_polynomial,
            );

            run_zk_whir_pcs_prover(
                vec![commitment.commitment_to_witness],
                vec![commitment.masked_polynomial, commitment.random_polynomial],
                weights
                    .into_iter()
                    .map(|w| vec![Box::new(w) as Box<dyn LinearForm<FieldElement>>])
                    .collect(),
                evaluations,
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
                    &c1.masked_polynomial,
                    &c1.random_polynomial,
                    alphas_1,
                );

            let (weights_2, f_sums_2, g_sums_2) =
                create_weights_and_evaluations_for_two_polynomials::<3>(
                    self.m,
                    &c2.masked_polynomial,
                    &c2.random_polynomial,
                    alphas_2,
                );

            // Compute cross-evaluations: weights_1 on c2's polynomials and
            // weights_2 on c1's polynomials. Whir's prove() expects evaluations
            // for ALL (weight, polynomial) pairs in row-major order.
            // Each dot product is over ~2M elements; run all 4 groups in parallel.
            let ((cross_f_12, cross_g_12), (cross_f_21, cross_g_21)) = rayon::join(
                || {
                    rayon::join(
                        || {
                            weights_1
                                .iter()
                                .map(|w| {
                                    let n = w.vector.len();
                                    dot(&w.vector, &c2.masked_polynomial[..n])
                                })
                                .collect::<Vec<_>>()
                        },
                        || {
                            weights_1
                                .iter()
                                .map(|w| {
                                    let n = w.vector.len();
                                    dot(&w.vector, &c2.random_polynomial[..n])
                                })
                                .collect::<Vec<_>>()
                        },
                    )
                },
                || {
                    rayon::join(
                        || {
                            weights_2
                                .iter()
                                .map(|w| {
                                    let n = w.vector.len();
                                    dot(&w.vector, &c1.masked_polynomial[..n])
                                })
                                .collect::<Vec<_>>()
                        },
                        || {
                            weights_2
                                .iter()
                                .map(|w| {
                                    let n = w.vector.len();
                                    dot(&w.vector, &c1.random_polynomial[..n])
                                })
                                .collect::<Vec<_>>()
                        },
                    )
                },
            );

            merlin.prover_hint_ark(&(f_sums_1, g_sums_1));
            merlin.prover_hint_ark(&(f_sums_2, g_sums_2));
            merlin.prover_hint_ark(&(cross_f_12, cross_g_12));
            merlin.prover_hint_ark(&(cross_f_21, cross_g_21));

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
                    &c1.masked_polynomial,
                    &c1.random_polynomial,
                    &c2.masked_polynomial,
                    &c2.random_polynomial,
                    public_weight,
                )
            };

            merlin.prover_hint_ark(&(public_f1, public_g1, public_f2, public_g2));

            // Combine weights from both commitments
            let mut all_weights = weights_1;
            all_weights.extend(weights_2);

            // Build evaluations in row-major order: evaluations[w_idx * 4 + p_idx]
            let evaluations: Vec<FieldElement> = all_weights
                .par_iter()
                .flat_map_iter(|w| {
                    let n = w.vector.len();
                    [
                        dot(&w.vector, &c1.masked_polynomial[..n]),
                        dot(&w.vector, &c1.random_polynomial[..n]),
                        dot(&w.vector, &c2.masked_polynomial[..n]),
                        dot(&w.vector, &c2.random_polynomial[..n]),
                    ]
                })
                .collect();

            run_zk_whir_pcs_prover(
                vec![c1.commitment_to_witness, c2.commitment_to_witness],
                vec![
                    c1.masked_polynomial,
                    c1.random_polynomial,
                    c2.masked_polynomial,
                    c2.random_polynomial,
                ],
                all_weights
                    .into_iter()
                    .map(|w| vec![Box::new(w) as Box<dyn LinearForm<FieldElement>>])
                    .collect(),
                evaluations,
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
    witness: Vec<FieldElement>,
    merlin: &mut ProverState<TranscriptSponge>,
) -> (WhirWitness, Vec<FieldElement>, Vec<FieldElement>) {
    let num_variables = witness.len().trailing_zeros() as usize;
    let mask = generate_random_multilinear_polynomial(num_variables);
    let masked_polynomial = create_masked_polynomial(witness, &mask);
    drop(mask);

    let random_polynomial = generate_random_multilinear_polynomial(m);

    let witness_new = whir_config.commit(merlin, &[&masked_polynomial, &random_polynomial]);

    (witness_new, masked_polynomial, random_polynomial)
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
    merlin: &mut ProverState<TranscriptSponge>,
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

    let blinding_polynomial_variables = flat.len().trailing_zeros() as usize;
    let (commitment_to_blinding_polynomial, blindings_mask_polynomial, blindings_blind_polynomial) =
        batch_commit_to_polynomial(
            blinding_polynomial_variables + 1,
            whir_for_blinding_of_spartan_config,
            flat,
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
            [expand_powers(alpha.as_slice())],
        );

    merlin.prover_message(&blinding_mask_polynomial_sum[0]);
    merlin.prover_message(&blinding_blind_polynomial_sum[0]);

    let blinding_evaluations = compute_evaluations_single(
        &blinding_weights,
        &blindings_mask_polynomial,
        &blindings_blind_polynomial,
    );

    let (_sums, _deferred) = run_zk_whir_pcs_prover(
        vec![commitment_to_blinding_polynomial],
        vec![blindings_mask_polynomial, blindings_blind_polynomial],
        blinding_weights
            .into_iter()
            .map(|w| vec![Box::new(w) as Box<dyn LinearForm<FieldElement>>])
            .collect(),
        blinding_evaluations,
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
    f_polynomial: &[FieldElement],
    g_polynomial: &[FieldElement],
    alphas: [Vec<FieldElement>; N],
) -> (Vec<PrefixCovector>, Vec<FieldElement>, Vec<FieldElement>) {
    let base_nv = cfg_nv.checked_sub(1).expect("cfg_nv >= 1");
    let base_len = 1usize << base_nv;
    let final_len = 1usize << cfg_nv;

    let mut weights = Vec::with_capacity(N);
    let mut f_sums = Vec::with_capacity(N);
    let mut g_sums = Vec::with_capacity(N);

    for mut w in alphas {
        if w.len() < base_len {
            w.resize(base_len, FieldElement::zero());
        } else {
            assert_eq!(w.len(), base_len);
        }

        f_sums.push(dot(&w, &f_polynomial[..base_len]));
        g_sums.push(dot(&w, &g_polynomial[..base_len]));

        weights.push(PrefixCovector::new(w, final_len));
    }

    (weights, f_sums, g_sums)
}

fn compute_evaluations_single(
    weights: &[PrefixCovector],
    masked_poly: &[FieldElement],
    random_poly: &[FieldElement],
) -> Vec<FieldElement> {
    weights
        .par_iter()
        .flat_map_iter(|w| {
            let n = w.vector.len();
            [
                dot(&w.vector, &masked_poly[..n]),
                dot(&w.vector, &random_poly[..n]),
            ]
        })
        .collect()
}

#[instrument(skip_all)]
pub fn run_zk_whir_pcs_prover(
    witnesses: Vec<WhirWitness>,
    vectors: Vec<Vec<FieldElement>>,
    linear_forms: Vec<Vec<Box<dyn LinearForm<FieldElement>>>>,
    evaluations: Vec<FieldElement>,
    params: &WhirConfig,
    merlin: &mut ProverState<TranscriptSponge>,
) -> (MultilinearPoint<FieldElement>, Vec<FieldElement>) {
    debug!("WHIR Parameters: {params}");

    let flat_linear_forms: Vec<Box<dyn LinearForm<FieldElement>>> =
        linear_forms.into_iter().flatten().collect();
    let cow_vectors: Vec<Cow<'_, [FieldElement]>> = vectors.into_iter().map(Cow::Owned).collect();
    let cow_witnesses: Vec<Cow<'_, WhirWitness>> = witnesses.into_iter().map(Cow::Owned).collect();
    let (randomness, deferred) = params.prove(
        merlin,
        cow_vectors,
        cow_witnesses,
        flat_linear_forms,
        Cow::Owned(evaluations),
    );

    (randomness, deferred)
}

fn compute_public_weight_evaluations(
    weights: &mut Vec<PrefixCovector>,
    f_polynomial: &[FieldElement],
    g_polynomial: &[FieldElement],
    public_weights: PrefixCovector,
) -> (FieldElement, FieldElement) {
    let n = public_weights.vector.len();
    let f = dot(&public_weights.vector, &f_polynomial[..n]);
    let g = dot(&public_weights.vector, &g_polynomial[..n]);
    weights.insert(0, public_weights);
    (f, g)
}

fn compute_public_weight_evaluations_dual(
    weights_1: &mut Vec<PrefixCovector>,
    c1_masked: &[FieldElement],
    c1_random: &[FieldElement],
    c2_masked: &[FieldElement],
    c2_random: &[FieldElement],
    public_weights: PrefixCovector,
) -> (FieldElement, FieldElement, FieldElement, FieldElement) {
    let n = public_weights.vector.len();
    let f1 = dot(&public_weights.vector, &c1_masked[..n]);
    let g1 = dot(&public_weights.vector, &c1_random[..n]);
    let f2 = dot(&public_weights.vector, &c2_masked[..n]);
    let g2 = dot(&public_weights.vector, &c2_random[..n]);
    weights_1.insert(0, public_weights);
    (f1, g1, f2, g2)
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ff::UniformRand, whir::algebra::linear_form::Covector};

    fn make_full_covector(prefix: &[FieldElement], logical_size: usize) -> Covector<FieldElement> {
        let mut full = prefix.to_vec();
        full.resize(logical_size, FieldElement::zero());
        Covector::new(full)
    }

    #[test]
    fn prefix_covector_size() {
        let pc = PrefixCovector::new(vec![FieldElement::one(); 4], 16);
        assert_eq!(pc.size(), 16);
    }

    #[test]
    fn prefix_covector_mle_evaluate_matches_full() {
        let mut rng = ark_std::rand::thread_rng();

        for (prefix_len, logical_size) in [(2usize, 8usize), (4, 16), (4, 4), (8, 32)] {
            let prefix: Vec<FieldElement> = (0..prefix_len)
                .map(|_| FieldElement::rand(&mut rng))
                .collect();

            let num_vars = logical_size.trailing_zeros() as usize;
            let point: Vec<FieldElement> = (0..num_vars)
                .map(|_| FieldElement::rand(&mut rng))
                .collect();

            let pc = PrefixCovector::new(prefix.clone(), logical_size);
            let full = make_full_covector(&prefix, logical_size);

            let pc_eval = pc.mle_evaluate(&point);
            let full_eval = full.mle_evaluate(&point);

            assert_eq!(
                pc_eval, full_eval,
                "mle_evaluate mismatch for prefix_len={prefix_len}, logical_size={logical_size}"
            );
        }
    }

    #[test]
    fn prefix_covector_accumulate_matches_full() {
        let mut rng = ark_std::rand::thread_rng();
        let prefix: Vec<FieldElement> = (0..4).map(|_| FieldElement::rand(&mut rng)).collect();
        let scalar = FieldElement::rand(&mut rng);
        let logical_size = 16;

        let pc = PrefixCovector::new(prefix.clone(), logical_size);
        let full = make_full_covector(&prefix, logical_size);

        let mut acc_pc = vec![FieldElement::zero(); logical_size];
        let mut acc_full = vec![FieldElement::zero(); logical_size];

        pc.accumulate(&mut acc_pc, scalar);
        full.accumulate(&mut acc_full, scalar);

        assert_eq!(acc_pc, acc_full, "accumulate mismatch");
    }

    #[test]
    fn prefix_covector_prefix_equals_logical_size() {
        let mut rng = ark_std::rand::thread_rng();
        let prefix: Vec<FieldElement> = (0..8).map(|_| FieldElement::rand(&mut rng)).collect();
        let point: Vec<FieldElement> = (0..3).map(|_| FieldElement::rand(&mut rng)).collect();

        let pc = PrefixCovector::new(prefix.clone(), 8);
        let full = make_full_covector(&prefix, 8);

        assert_eq!(pc.mle_evaluate(&point), full.mle_evaluate(&point));
    }
}

fn get_public_weights(
    public_inputs: &PublicInputs,
    merlin: &mut ProverState<TranscriptSponge>,
    m: usize,
) -> PrefixCovector {
    let public_inputs_hash = public_inputs.hash();
    merlin.prover_message(&public_inputs_hash);

    let x: FieldElement = merlin.verifier_message();

    let domain_size = 1 << m;
    // Only allocate the non-zero prefix: public_inputs.len() entries are non-zero,
    // PrefixCovector zero-pads the rest via logical_size.
    let prefix_len = public_inputs.len().next_power_of_two().max(2);
    let mut public_weights = vec![FieldElement::zero(); prefix_len];

    let mut current_pow = FieldElement::one();
    for slot in public_weights.iter_mut().take(public_inputs.len()) {
        *slot = current_pow;
        current_pow *= x;
    }

    PrefixCovector {
        vector:       public_weights,
        logical_size: domain_size,
        deferred:     false,
    }
}
