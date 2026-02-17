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
            zk_utils::{coeffs_to_evals, covector_dot},
            HALF,
        },
        FieldElement, PublicInputs, TranscriptSponge, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig,
        R1CS,
    },
    std::mem,
    tracing::instrument,
    whir::{
        algebra::{
            linear_form::{Covector, LinearForm},
            polynomials::{CoefficientList, EvaluationsList},
        },
        protocols::whir_zk,
        transcript::{ProverState, VerifierMessage},
    },
};

pub struct WhirR1CSCommitment {
    pub zk_witness:         whir_zk::Witness<FieldElement>,
    pub witness_polynomial: CoefficientList<FieldElement>,
    pub padded_witness:     Vec<FieldElement>,
}

pub trait WhirR1CSProver {
    fn commit(
        &self,
        merlin: &mut ProverState<TranscriptSponge>,
        r1cs: &R1CS,
        witness: Vec<FieldElement>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment>;

    fn prove(
        &self,
        merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof>;
}

impl WhirR1CSProver for WhirR1CSScheme {
    #[instrument(skip_all)]
    fn commit(
        &self,
        merlin: &mut ProverState<TranscriptSponge>,
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

        let poly_len = 1usize << self.m;

        // Pad witness to power-of-two, then extend to poly_len with zeros.
        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < poly_len {
            padded_witness.resize(poly_len, FieldElement::zero());
        }

        // Convert to coefficient form for whir_zk.
        let witness_polynomial = EvaluationsList::new(padded_witness.clone()).to_coeffs();

        // Commit using whir_zk — handles blinding internally.
        let whir_zk_config = self.whir_zk_witness();
        let zk_witness = whir_zk_config.commit(merlin, &[&witness_polynomial]);

        Ok(WhirR1CSCommitment {
            zk_witness,
            witness_polynomial,
            padded_witness,
        })
    }

    #[instrument(skip_all)]
    fn prove(
        &self,
        mut merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        mut commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        let is_single = commitments.len() == 1;

        // Reconstruct full witness for sumcheck
        let full_witness: Vec<FieldElement> = if is_single {
            let mut w = mem::take(&mut commitments[0].padded_witness);
            w.truncate(r1cs.num_witnesses());
            w
        } else {
            let mut w = mem::take(&mut commitments[0].padded_witness);
            w.truncate(self.w1_size);
            let w2_len = r1cs.num_witnesses() - self.w1_size;
            w.extend_from_slice(&commitments[1].padded_witness[..w2_len]);
            commitments[1].padded_witness = Vec::new();
            w
        };

        // First round: ZK sumcheck to reduce R1CS to weighted evaluation
        let whir_zk_spartan = self.whir_zk_spartan();
        let alpha = run_zk_sumcheck_prover(
            &r1cs,
            &full_witness,
            &mut merlin,
            self.m_0,
            &whir_zk_spartan,
        );
        drop(full_witness);

        // Compute weights from R1CS matrices
        let alphas = calculate_external_row_of_r1cs_matrices(alpha, r1cs);
        let public_weight = get_public_weights(public_inputs, &mut merlin, self.m);

        let whir_zk_witness = self.whir_zk_witness();

        if is_single {
            prove_single(
                &mut merlin,
                &whir_zk_witness,
                commitments.into_iter().next().unwrap(),
                &alphas,
                public_weight,
                public_inputs,
                self.m,
            );
        } else {
            let mut commitments = commitments.into_iter();
            let c1 = commitments.next().unwrap();
            let c2 = commitments.next().unwrap();
            prove_dual(
                &mut merlin,
                &whir_zk_witness,
                c1,
                c2,
                alphas,
                public_weight,
                public_inputs,
                self.m,
                self.w1_size,
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

/// Single commitment prove path.
fn prove_single(
    merlin: &mut ProverState<TranscriptSponge>,
    whir_zk_config: &WhirZkConfig,
    commitment: WhirR1CSCommitment,
    alphas: &[Vec<FieldElement>; 3],
    public_weight: Covector<FieldElement>,
    public_inputs: &PublicInputs,
    m: usize,
) {
    let poly_len = 1usize << m;
    let poly_evals = coeffs_to_evals(&commitment.witness_polynomial);

    // Build weights and compute evaluations
    let mut weights: Vec<Covector<FieldElement>> = Vec::with_capacity(3);
    let mut eval_values: Vec<FieldElement> = Vec::with_capacity(3);

    for alpha_row in alphas {
        let mut w = alpha_row.clone();
        w.resize(poly_len, FieldElement::zero());
        let weight = Covector::new(w);
        eval_values.push(covector_dot(&weight, &poly_evals));
        weights.push(weight);
    }

    // Send evaluations as hint
    merlin.prover_hint_ark(&eval_values);

    // Handle public weight
    let public_eval = if public_inputs.is_empty() {
        FieldElement::zero()
    } else {
        let eval = covector_dot(&public_weight, &poly_evals);
        weights.insert(0, public_weight);
        eval
    };
    merlin.prover_hint_ark(&public_eval);

    let weight_refs: Vec<&dyn LinearForm<FieldElement>> = weights
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();

    // Prepend public evaluation if we have public inputs
    let all_evals = if public_inputs.is_empty() {
        eval_values
    } else {
        let mut all = vec![public_eval];
        all.extend(eval_values);
        all
    };

    whir_zk_config.prove(
        merlin,
        &[&commitment.witness_polynomial],
        &commitment.zk_witness,
        &weight_refs,
        &all_evals,
    );
}

/// Dual commitment prove path.
#[allow(clippy::too_many_arguments)]
fn prove_dual(
    merlin: &mut ProverState<TranscriptSponge>,
    whir_zk_config: &WhirZkConfig,
    c1: WhirR1CSCommitment,
    c2: WhirR1CSCommitment,
    alphas: [Vec<FieldElement>; 3],
    public_weight: Covector<FieldElement>,
    public_inputs: &PublicInputs,
    m: usize,
    w1_size: usize,
) {
    let poly_len = 1usize << m;

    // Split alphas between w1 and w2
    let (alphas_1, alphas_2): (Vec<_>, Vec<_>) = alphas
        .into_iter()
        .map(|mut v| {
            let v2 = v.split_off(w1_size);
            (v, v2)
        })
        .unzip();

    let alphas_1: [Vec<FieldElement>; 3] = alphas_1.try_into().unwrap();
    let alphas_2: [Vec<FieldElement>; 3] = alphas_2.try_into().unwrap();

    let poly_evals_1 = coeffs_to_evals(&c1.witness_polynomial);
    let poly_evals_2 = coeffs_to_evals(&c2.witness_polynomial);

    // Build weights and evaluations for c1
    let mut weights_1: Vec<Covector<FieldElement>> = Vec::with_capacity(3);
    let mut evals_1: Vec<FieldElement> = Vec::with_capacity(3);
    for alpha_row in &alphas_1 {
        let mut w = alpha_row.clone();
        w.resize(poly_len, FieldElement::zero());
        let weight = Covector::new(w);
        evals_1.push(covector_dot(&weight, &poly_evals_1));
        weights_1.push(weight);
    }

    // Build weights and evaluations for c2
    let mut weights_2: Vec<Covector<FieldElement>> = Vec::with_capacity(3);
    let mut evals_2: Vec<FieldElement> = Vec::with_capacity(3);
    for alpha_row in &alphas_2 {
        let mut w = alpha_row.clone();
        w.resize(poly_len, FieldElement::zero());
        let weight = Covector::new(w);
        evals_2.push(covector_dot(&weight, &poly_evals_2));
        weights_2.push(weight);
    }

    // Send evaluations as hints
    merlin.prover_hint_ark(&evals_1);
    merlin.prover_hint_ark(&evals_2);

    let (public_eval_1, public_eval_2) = if public_inputs.is_empty() {
        (FieldElement::zero(), FieldElement::zero())
    } else {
        let e1 = covector_dot(&public_weight, &poly_evals_1);
        let e2 = covector_dot(&public_weight, &poly_evals_2);
        // Covector doesn't impl Clone — build a second one from the same vector
        let mut pw2 = Covector::new(public_weight.vector.clone());
        pw2.deferred = false;
        weights_1.insert(0, public_weight);
        weights_2.insert(0, pw2);
        (e1, e2)
    };
    merlin.prover_hint_ark(&(public_eval_1, public_eval_2));

    // Build final eval vectors with public eval prepended if needed
    let all_evals_1 = if public_inputs.is_empty() {
        evals_1
    } else {
        let mut all = vec![public_eval_1];
        all.extend(evals_1);
        all
    };
    let all_evals_2 = if public_inputs.is_empty() {
        evals_2
    } else {
        let mut all = vec![public_eval_2];
        all.extend(evals_2);
        all
    };

    let weight_refs_1: Vec<&dyn LinearForm<FieldElement>> = weights_1
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();
    let weight_refs_2: Vec<&dyn LinearForm<FieldElement>> = weights_2
        .iter()
        .map(|w| w as &dyn LinearForm<FieldElement>)
        .collect();

    // Two separate whir_zk prove calls — one per commitment
    whir_zk_config.prove(
        merlin,
        &[&c1.witness_polynomial],
        &c1.zk_witness,
        &weight_refs_1,
        &all_evals_1,
    );
    whir_zk_config.prove(
        merlin,
        &[&c2.witness_polynomial],
        &c2.zk_witness,
        &weight_refs_2,
        &all_evals_2,
    );
}

// ── Spartan sumcheck ─────────────────────────────────────────────────

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
    whir_zk_spartan: &WhirZkConfig,
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

    // Flatten blinding polynomial into evaluations and convert to coefficient form
    let blinding_nv = whir_zk_spartan.num_witness_variables();
    let target_b = 1usize << blinding_nv;

    let mut flat = blinding_polynomial
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    if flat.len() < target_b {
        flat.resize(target_b, FieldElement::zero());
    }

    let blinding_coeff_list = EvaluationsList::new(flat).to_coeffs();

    // Commit using whir_zk — handles blinding internally.
    let blinding_witness = whir_zk_spartan.commit(merlin, &[&blinding_coeff_list]);

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

    // Build weight for the blinding polynomial evaluation
    let blinding_weight_vec = expand_powers(alpha.as_slice());
    let blinding_poly_len = 1usize << blinding_nv;
    let mut w_full = blinding_weight_vec;
    w_full.resize(blinding_poly_len, FieldElement::zero());
    let blinding_weight = Covector::new(w_full);

    let blinding_evals = coeffs_to_evals(&blinding_coeff_list);
    let blinding_eval = covector_dot(&blinding_weight, &blinding_evals);

    // Send single evaluation as prover message (verifier needs it for Spartan
    // check)
    merlin.prover_message(&blinding_eval);

    let weight_refs: Vec<&dyn LinearForm<FieldElement>> =
        vec![&blinding_weight as &dyn LinearForm<FieldElement>];

    whir_zk_spartan.prove(
        merlin,
        &[&blinding_coeff_list],
        &blinding_witness,
        &weight_refs,
        &[blinding_eval],
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

fn get_public_weights(
    public_inputs: &PublicInputs,
    merlin: &mut ProverState<TranscriptSponge>,
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
