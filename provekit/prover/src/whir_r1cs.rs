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
            HALF,
        },
        FieldElement, PublicInputs, TranscriptSponge, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig,
        R1CS,
    },
    tracing::instrument,
    whir::{
        algebra::{dot, linear_form::LinearForm, multilinear_extend},
        protocols::whir_zk::Witness as WhirZkWitness,
        transcript::{ProverState, VerifierMessage},
    },
};

pub struct WhirR1CSCommitment {
    pub witness:    WhirZkWitness<FieldElement>,
    pub polynomial: Vec<FieldElement>,
}

/// A covector that stores only a power-of-two prefix, with the rest
/// implicitly zero-padded to `logical_size`. Saves memory when the
/// covector is known to be zero beyond the prefix (e.g. R1CS alpha
/// weights that are zero-padded from witness_size to 2^m).
///
/// Implements [`LinearForm`] so it can be passed directly to whir's
/// `prove()` in place of a full-length `Covector`.
struct PrefixCovector {
    /// The non-zero prefix. Length must be a power of two.
    vector:       Vec<FieldElement>,
    /// The full logical domain size (also a power of two, >= vector.len()).
    logical_size: usize,
    deferred:     bool,
}

impl PrefixCovector {
    fn non_deferred(vector: Vec<FieldElement>, logical_size: usize) -> Self {
        debug_assert!(vector.len().is_power_of_two());
        debug_assert!(logical_size.is_power_of_two());
        debug_assert!(logical_size >= vector.len());
        Self {
            vector,
            logical_size,
            deferred: false,
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
        let r = point.len() - k;
        let head_factor: FieldElement =
            point[..r].iter().map(|p| FieldElement::one() - p).product();
        let prefix_mle = multilinear_extend(&self.vector, &point[r..]);
        head_factor * prefix_mle
    }

    fn accumulate(&self, accumulator: &mut [FieldElement], scalar: FieldElement) {
        for (acc, val) in accumulator[..self.vector.len()]
            .iter_mut()
            .zip(&self.vector)
        {
            *acc += scalar * *val;
        }
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

        let num_vars = self.whir_witness.num_witness_variables();
        let target_len = 1usize << num_vars;

        // Pad witness to power-of-two, then extend to target_len with zeros.
        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < target_len {
            padded_witness.resize(target_len, FieldElement::zero());
        }

        // zkWHIR 2.0: commit handles masking/blinding internally.
        let zk_witness = self.whir_witness.commit(merlin, &[&padded_witness]);

        Ok(WhirR1CSCommitment {
            witness:    zk_witness,
            polynomial: padded_witness,
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
        let (x, public_weight) = get_public_weights(public_inputs, &mut merlin, self.m);

        if is_single {
            let commitment = commitments.into_iter().next().unwrap();
            let (mut weights, evals) =
                create_weights_and_evaluations::<3>(self.m, &commitment.polynomial, alphas);

            merlin.prover_hint_ark(&evals);

            let public_eval = if public_inputs.is_empty() {
                FieldElement::zero()
            } else {
                compute_public_weight_evaluation(
                    &mut weights,
                    &commitment.polynomial,
                    public_weight,
                )
            };

            merlin.prover_hint_ark(&public_eval);

            let evaluations = compute_evaluations(&weights, &commitment.polynomial);

            let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
                .iter()
                .map(|w| w as &dyn LinearForm<FieldElement>)
                .collect();
            self.whir_witness.prove(
                &mut merlin,
                &[&commitment.polynomial],
                commitment.witness,
                &weight_refs,
                &evaluations,
            );
        } else {
            // Dual commitment path: separate prove per polynomial.
            // Structured to minimise peak memory — c1 data (polynomial +
            // witness + weights) is freed before c2's prove begins.
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

            // Phase 1 — compute all transcript hints (cheap dot products,
            // no PrefixCovector allocation).  Both polynomials must be
            // accessible here but we defer weight construction.
            let evals_1 = compute_alpha_evals(&c1.polynomial, &alphas_1);
            let evals_2 = compute_alpha_evals(&c2.polynomial, &alphas_2);
            merlin.prover_hint_ark(&evals_1);
            merlin.prover_hint_ark(&evals_2);

            let (public_1, public_2) = if !public_inputs.is_empty() {
                let p1 = compute_public_eval(x, public_inputs.len(), &c1.polynomial);
                let p2 = compute_public_eval(x, public_inputs.len(), &c2.polynomial);
                merlin.prover_hint_ark(&p1);
                merlin.prover_hint_ark(&p2);
                (Some(p1), Some(p2))
            } else {
                merlin.prover_hint_ark(&FieldElement::zero());
                merlin.prover_hint_ark(&FieldElement::zero());
                (None, None)
            };

            // Phase 2 — prove c1, then drop all c1 data.
            let WhirR1CSCommitment {
                witness: w1,
                polynomial: p1,
            } = c1;
            {
                let mut weights = build_prefix_covectors(self.m, alphas_1);
                let mut evaluations: Vec<FieldElement> = Vec::new();
                if let Some(pe) = public_1 {
                    weights.insert(0, make_public_weight(x, public_inputs.len(), self.m));
                    evaluations.push(pe);
                }
                evaluations.extend_from_slice(&evals_1);

                let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
                    .iter()
                    .map(|w| w as &dyn LinearForm<FieldElement>)
                    .collect();
                self.whir_witness
                    .prove(&mut merlin, &[&p1], w1, &weight_refs, &evaluations);
            }
            drop(p1);

            // Phase 3 — prove c2.
            let WhirR1CSCommitment {
                witness: w2,
                polynomial: p2,
            } = c2;
            {
                let mut weights = build_prefix_covectors(self.m, alphas_2);
                let mut evaluations: Vec<FieldElement> = Vec::new();
                if let Some(pe) = public_2 {
                    weights.insert(0, make_public_weight(x, public_inputs.len(), self.m));
                    evaluations.push(pe);
                }
                evaluations.extend_from_slice(&evals_2);

                let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
                    .iter()
                    .map(|w| w as &dyn LinearForm<FieldElement>)
                    .collect();
                self.whir_witness
                    .prove(&mut merlin, &[&p2], w2, &weight_refs, &evaluations);
            }
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
        None => min,
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
    whir_for_blinding_of_spartan_config: &WhirZkConfig,
) -> Vec<FieldElement> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let r: Vec<FieldElement> = merlin.verifier_message_vec(m_0);
    let ((mut a, mut b, mut c), mut eq) = rayon::join(
        || calculate_witness_bounds(r1cs, z),
        || calculate_evaluations_over_boolean_hypercube_for_eq(r),
    );

    // Ensure each vector has length >= 2 and is a power of two.
    pad_to_pow2_len_min2(&mut a);
    pad_to_pow2_len_min2(&mut b);
    pad_to_pow2_len_min2(&mut c);
    pad_to_pow2_len_min2(&mut eq);

    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);

    let blinding_polynomial = generate_blinding_spartan_univariate_polys(m_0);

    // zkWHIR 2.0: the config tells us the number of witness variables.
    let spartan_num_vars = whir_for_blinding_of_spartan_config.num_witness_variables();
    let target_b = 1usize << spartan_num_vars;

    // Flatten cubic blinding coefficients and pad to target size.
    let mut flat: Vec<FieldElement> = blinding_polynomial.iter().flatten().cloned().collect();

    if flat.len() < target_b {
        flat.resize(target_b, FieldElement::zero());
    }

    // zkWHIR 2.0 commit: handles masking/blinding internally.
    let blinding_witness = whir_for_blinding_of_spartan_config.commit(merlin, &[&flat]);

    let sum_g_reduce = sum_over_hypercube(&blinding_polynomial);

    merlin.prover_message(&sum_g_reduce);

    let rho: FieldElement = merlin.verifier_message();

    // Instead of proving that sum of F over the boolean hypercube is 0, we prove
    // that sum of F + rho * G over the boolean hypercube is rho * Sum G.
    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_reduce;

    let mut fold = None;

    for idx in 0..m_0 {
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

    // Build weight for the blinding polynomial evaluation.
    let mut weight_vec = expand_powers(alpha.as_slice());
    let weight_domain_size = 1usize << spartan_num_vars;
    if weight_vec.len() < weight_domain_size {
        weight_vec.resize(weight_domain_size, FieldElement::zero());
    }

    let blinding_eval = dot(&weight_vec, &flat[..weight_vec.len()]);
    merlin.prover_message(&blinding_eval);

    let covector = PrefixCovector::non_deferred(weight_vec, weight_domain_size);
    let weight_refs: Vec<&dyn LinearForm<FieldElement>> =
        vec![&covector as &dyn LinearForm<FieldElement>];
    whir_for_blinding_of_spartan_config.prove(merlin, &[&flat], blinding_witness, &weight_refs, &[
        blinding_eval,
    ]);

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

/// Compute dot products of alpha vectors against a polynomial without
/// allocating PrefixCovector weights.  Used to write transcript hints
/// before deferring weight construction (saves memory in dual-commit).
fn compute_alpha_evals<const N: usize>(
    polynomial: &[FieldElement],
    alphas: &[Vec<FieldElement>; N],
) -> Vec<FieldElement> {
    alphas
        .iter()
        .map(|w| {
            w.iter()
                .zip(&polynomial[..w.len()])
                .map(|(a, b)| *a * *b)
                .sum()
        })
        .collect()
}

/// Build PrefixCovectors from alpha vectors, consuming the alphas.
fn build_prefix_covectors<const N: usize>(
    m: usize,
    alphas: [Vec<FieldElement>; N],
) -> Vec<PrefixCovector> {
    let domain_size = 1usize << m;
    alphas
        .into_iter()
        .map(|mut w| {
            let base_len = w.len().next_power_of_two().max(2);
            w.resize(base_len, FieldElement::zero());
            PrefixCovector::non_deferred(w, domain_size)
        })
        .collect()
}

/// Compute the public weight evaluation ⟨[1, x, x², …], poly⟩ without
/// allocating a PrefixCovector.
fn compute_public_eval(
    x: FieldElement,
    public_inputs_len: usize,
    polynomial: &[FieldElement],
) -> FieldElement {
    let mut eval = FieldElement::zero();
    let mut x_pow = FieldElement::one();
    for &p in polynomial.iter().take(public_inputs_len) {
        eval += x_pow * p;
        x_pow *= x;
    }
    eval
}

/// Create weights and compute evaluations for a single polynomial.
fn create_weights_and_evaluations<const N: usize>(
    m: usize,
    polynomial: &[FieldElement],
    alphas: [Vec<FieldElement>; N],
) -> (Vec<PrefixCovector>, Vec<FieldElement>) {
    let domain_size = 1usize << m;

    let mut weights = Vec::with_capacity(N);
    let mut evals = Vec::with_capacity(N);

    for mut w in alphas {
        let base_len = w.len().next_power_of_two().max(2);
        w.resize(base_len, FieldElement::zero());

        evals.push(dot(&w, &polynomial[..base_len]));
        weights.push(PrefixCovector::non_deferred(w, domain_size));
    }

    (weights, evals)
}

/// Compute evaluations of weights against a single polynomial.
fn compute_evaluations(
    weights: &[PrefixCovector],
    polynomial: &[FieldElement],
) -> Vec<FieldElement> {
    weights
        .iter()
        .map(|w| dot(&w.vector, &polynomial[..w.vector.len()]))
        .collect()
}

fn compute_public_weight_evaluation(
    weights: &mut Vec<PrefixCovector>,
    polynomial: &[FieldElement],
    public_weights: PrefixCovector,
) -> FieldElement {
    let n = public_weights.vector.len();
    let eval = dot(&public_weights.vector, &polynomial[..n]);
    weights.insert(0, public_weights);
    eval
}

/// Interact with the transcript for public input verification and return
/// the public weight randomness `x` along with the first weight instance.
fn get_public_weights(
    public_inputs: &PublicInputs,
    merlin: &mut ProverState<TranscriptSponge>,
    m: usize,
) -> (FieldElement, PrefixCovector) {
    let public_inputs_hash = public_inputs.hash();
    merlin.prover_message(&public_inputs_hash);

    let x: FieldElement = merlin.verifier_message();

    (x, make_public_weight(x, public_inputs.len(), m))
}

/// Create a public weight PrefixCovector from randomness `x`.
fn make_public_weight(x: FieldElement, public_inputs_len: usize, m: usize) -> PrefixCovector {
    let domain_size = 1 << m;
    let prefix_len = public_inputs_len.next_power_of_two().max(2);
    let mut public_weights = vec![FieldElement::zero(); prefix_len];

    let mut current_pow = FieldElement::one();
    for slot in public_weights.iter_mut().take(public_inputs_len) {
        *slot = current_pow;
        current_pow *= x;
    }

    PrefixCovector::non_deferred(public_weights, domain_size)
}
