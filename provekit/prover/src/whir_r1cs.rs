use {
    ::tracing::instrument,
    anyhow::{ensure, Result},
    ark_ff::Field,
    ark_std::{
        rand::distributions::{Distribution, Standard},
        Zero,
    },
    provekit_common::{
        prefix_covector::{
            build_prefix_covectors, compute_alpha_evals, compute_challenge_eval,
            compute_public_eval, expand_powers, make_challenge_weight, make_public_weight,
            OffsetCovector,
        },
        utils::{
            pad_to_power_of_two,
            sumcheck::{
                calculate_evaluations_over_boolean_hypercube_for_eq, calculate_witness_bounds,
                eval_cubic_poly, multiply_transposed_by_eq_alpha, sumcheck_fold_map_reduce,
                transpose_r1cs_matrices,
            },
        },
        Base, Ext, FieldHash, PrefixCovector, ProofField, PublicInputs, WhirR1CSProof,
        WhirR1CSScheme, R1CS,
    },
    std::borrow::Cow,
    whir::{
        algebra::{
            dot,
            embedding::{Embedding, Identity},
            linear_form::LinearForm,
            mixed_dot,
        },
        protocols::whir::Witness as WhirWitness,
        transcript::{Codec, DuplexSpongeInterface, ProverState, VerifierMessage},
    },
};

/// Spartan sumcheck blinding `g`, committed separately in the extension field.
pub struct BlindingState<P: ProofField> {
    /// The `m_0` cubic blinding univariates (4 ext coefficients each).
    pub polynomial: Vec<[Ext<P>; 4]>,
    /// `polynomial` flattened (length `4 * m_0`) and zero-padded to the
    /// blinding commitment domain — the vector actually committed.
    pub vector:     Vec<Ext<P>>,
    /// WHIR witness for the ext blinding commitment.
    pub witness:    WhirWitness<Ext<P>, Identity<Ext<P>>>,
}

pub struct WhirR1CSCommitment<P: ProofField> {
    pub witness:    WhirWitness<Ext<P>, P::Embedding>,
    pub polynomial: Vec<Base<P>>,
    pub blinding:   Option<BlindingState<P>>,
}

pub trait WhirR1CSProver<P: FieldHash> {
    fn commit(
        &self,
        merlin: &mut ProverState<P::Sponge>,
        num_witnesses: usize,
        num_constraints: usize,
        witness: Vec<Base<P>>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment<P>>;

    fn prove_noir(
        &self,
        merlin: ProverState<P::Sponge>,
        r1cs: R1CS<Base<P>>,
        commitments: Vec<WhirR1CSCommitment<P>>,
        full_witness: Vec<Base<P>>,
        public_inputs: &PublicInputs<Base<P>>,
    ) -> Result<WhirR1CSProof>;
}

impl<P: FieldHash> WhirR1CSProver<P> for WhirR1CSScheme<P>
where
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    #[instrument(skip_all)]
    fn commit(
        &self,
        merlin: &mut ProverState<P::Sponge>,
        num_witnesses: usize,
        num_constraints: usize,
        witness: Vec<Base<P>>,
        is_w1: bool,
    ) -> Result<WhirR1CSCommitment<P>> {
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
            witness_size <= self.domain_size(),
            "R1CS witness length exceeds scheme capacity"
        );
        ensure!(
            num_constraints <= 1 << self.m_0,
            "R1CS constraints exceed scheme capacity"
        );

        let num_vars = self.whir_witness.initial_num_variables();
        let target_len = 1usize << num_vars;

        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < target_len {
            padded_witness.resize(target_len, <Base<P>>::zero());
        }

        // The non-ZK WHIR config commits the base-field witness directly. NOTE:
        // this commitment is NOT hiding — its query openings still leak witness
        // values (full witness ZK needs zkWHIR-v3). Sumcheck zero-knowledge is
        // provided by the separate ext blinding commitment below.
        let witness_commitment = self.whir_witness.commit(merlin, &[&padded_witness]);

        // Commit the Spartan sumcheck blinding `g` separately, natively in the
        // extension field. Transcript order: this commitment is absorbed
        // immediately after the witness commitment (mirrored in the verifier).
        let blinding = if is_w1 {
            let g = generate_blinding_univariates::<Ext<P>>(self.m_0);
            let blind_len = 1usize << self.whir_blinding.initial_num_variables();
            let mut g_vector: Vec<Ext<P>> = g.iter().flatten().copied().collect();
            g_vector.resize(blind_len, <Ext<P>>::zero());
            let blinding_witness = self.whir_blinding.commit(merlin, &[&g_vector]);
            Some(BlindingState {
                polynomial: g,
                vector:     g_vector,
                witness:    blinding_witness,
            })
        } else {
            None
        };

        Ok(WhirR1CSCommitment {
            witness: witness_commitment,
            polynomial: padded_witness,
            blinding,
        })
    }

    #[instrument(skip_all)]
    fn prove_noir(
        &self,
        mut merlin: ProverState<P::Sponge>,
        r1cs: R1CS<Base<P>>,
        commitments: Vec<WhirR1CSCommitment<P>>,
        full_witness: Vec<Base<P>>,
        public_inputs: &PublicInputs<Base<P>>,
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        let (a, b, c) = calculate_witness_bounds(&r1cs, &full_witness);
        drop(full_witness);

        // Witness bounds are computed in the base field; lift them to the
        // extension for the sumcheck (a no-op under the `Identity` embedding,
        // where base == ext).
        let embedding = <P::Embedding>::default();
        let (a, b, c) = (
            embedding.map_vec(a),
            embedding.map_vec(b),
            embedding.map_vec(c),
        );

        let blinding = commitments[0]
            .blinding
            .as_ref()
            .expect("c1 must carry blinding state");

        // The Spartan sumcheck runs entirely in the extension field; `g` is now
        // native ext, committed separately. `blinding_eval` opens the ext
        // blinding vector (which holds `g` flattened at offset 0).
        let (alpha, blinding_eval) = run_zk_sumcheck_prover(
            a,
            b,
            c,
            &mut merlin,
            self.m_0,
            &blinding.polynomial,
            &blinding.vector,
            0,
        );

        let (at, bt, ct) = transpose_r1cs_matrices(&r1cs);
        let alphas = multiply_transposed_by_eq_alpha(&embedding, &at, &bt, &ct, &alpha, &r1cs);

        let blinding_weights = expand_powers::<4, _>(&alpha);
        prove_from_alphas(
            self,
            merlin,
            alphas,
            blinding_eval,
            blinding_weights,
            commitments,
            public_inputs,
        )
    }
}

#[instrument(skip_all)]
pub fn prove_from_alphas<P: FieldHash>(
    scheme: &WhirR1CSScheme<P>,
    mut merlin: ProverState<P::Sponge>,
    alphas: [Vec<Ext<P>>; 3],
    blinding_eval: Ext<P>,
    blinding_weights: Vec<Ext<P>>,
    mut commitments: Vec<WhirR1CSCommitment<P>>,
    public_inputs: &PublicInputs<Base<P>>,
) -> Result<WhirR1CSProof>
where
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let public_inputs_hash = P::hash_public_inputs(scheme.hash_config, &public_inputs.0);
    let public_inputs_len = public_inputs.len();

    // The ext blinding commitment lives on c0; pull it out before the base
    // commitments are consumed below. It is opened at the very end, after all
    // base-witness opens (mirrored in the verifier).
    let blinding_state = commitments[0]
        .blinding
        .take()
        .expect("c0 must carry blinding state");

    let is_single = commitments.len() == 1;
    let (x, public_weight) =
        get_public_weights(public_inputs_hash, public_inputs_len, &mut merlin, scheme.m);

    // The committed witness is base-field; covectors and claimed evaluations are
    // extension-field. Evaluations are computed via mixed products through this
    // embedding (a no-op under `Identity`).
    let embedding = <P::Embedding>::default();

    if is_single {
        // Single commitment path
        let commitment = commitments
            .into_iter()
            .next()
            .expect("single-commitment path requires at least one commitment");
        let (mut weights, evals) = create_weights_and_evaluations::<3, _>(
            &embedding,
            scheme.m,
            &commitment.polynomial,
            alphas,
        );

        for eval in &evals {
            merlin.prover_message(eval);
        }

        if public_inputs_len > 0 {
            let public_eval = compute_public_weight_evaluation(
                &embedding,
                &mut weights,
                &commitment.polynomial,
                public_weight,
            );
            merlin.prover_message(&public_eval);
        }

        let evaluations = compute_evaluations(&embedding, &weights, &commitment.polynomial);

        let boxed_weights: Vec<Box<dyn LinearForm<Ext<P>>>> = weights
            .into_iter()
            .map(|w| Box::new(w) as Box<dyn LinearForm<Ext<P>>>)
            .collect();

        let _ = scheme.whir_witness.prove(
            &mut merlin,
            vec![Cow::Borrowed(commitment.polynomial.as_slice())],
            vec![Cow::Owned(commitment.witness)],
            boxed_weights,
            Cow::Borrowed(&evaluations),
        );
    } else {
        // Dual commitment path
        let mut commitments = commitments.into_iter();
        let c1 = commitments
            .next()
            .expect("dual-commitment path requires first commitment");
        let c2 = commitments
            .next()
            .expect("dual-commitment path requires second commitment");

        let (alphas_1, alphas_2): (Vec<_>, Vec<_>) = alphas
            .into_iter()
            .map(|mut v| {
                let v2 = v.split_off(scheme.w1_size);
                (v, v2)
            })
            .unzip();

        let alphas_1: [Vec<Ext<P>>; 3] = alphas_1
            .try_into()
            .expect("alphas_1 must have exactly 3 elements");
        let alphas_2: [Vec<Ext<P>>; 3] = alphas_2
            .try_into()
            .expect("alphas_2 must have exactly 3 elements");

        let evals_1 = compute_alpha_evals(&embedding, &c1.polynomial, &alphas_1);
        let evals_2 = compute_alpha_evals(&embedding, &c2.polynomial, &alphas_2);
        for eval in &evals_1 {
            merlin.prover_message(eval);
        }
        for eval in &evals_2 {
            merlin.prover_message(eval);
        }

        let public_1 = if public_inputs_len > 0 {
            let p1 = compute_public_eval(&embedding, x, public_inputs_len, &c1.polynomial);
            merlin.prover_message(&p1);
            Some(p1)
        } else {
            None
        };

        // Challenge binding: prove that w2 contains the correct Fiat-Shamir
        // challenge values at the expected positions.
        let challenge_eval = if !scheme.challenge_offsets.is_empty() {
            let ce =
                compute_challenge_eval(&embedding, x, &scheme.challenge_offsets, &c2.polynomial);
            merlin.prover_message(&ce);
            Some(ce)
        } else {
            None
        };

        let WhirR1CSCommitment {
            witness: w1,
            polynomial: p1,
            ..
        } = c1;
        {
            let mut weights = build_prefix_covectors(scheme.m, alphas_1);
            let mut evaluations: Vec<Ext<P>> = Vec::new();
            if let Some(pe) = public_1 {
                weights.insert(0, make_public_weight(x, public_inputs_len, scheme.m));
                evaluations.push(pe);
            }
            evaluations.extend_from_slice(&evals_1);

            let boxed_weights: Vec<Box<dyn LinearForm<Ext<P>>>> = weights
                .into_iter()
                .map(|w| Box::new(w) as Box<dyn LinearForm<Ext<P>>>)
                .collect();

            let _ = scheme.whir_witness.prove(
                &mut merlin,
                vec![Cow::Borrowed(p1.as_slice())],
                vec![Cow::Owned(w1)],
                boxed_weights,
                Cow::Borrowed(&evaluations),
            );
        }
        drop(p1);

        let WhirR1CSCommitment {
            witness: w2,
            polynomial: p2,
            ..
        } = c2;
        {
            let weights = build_prefix_covectors(scheme.m, alphas_2);
            let mut evaluations: Vec<Ext<P>> = evals_2;

            let mut boxed_weights: Vec<Box<dyn LinearForm<Ext<P>>>> = weights
                .into_iter()
                .map(|w| Box::new(w) as Box<dyn LinearForm<Ext<P>>>)
                .collect();

            if let Some(ce) = challenge_eval {
                let cw = make_challenge_weight(x, &scheme.challenge_offsets, scheme.m);
                evaluations.push(ce);
                boxed_weights.push(Box::new(cw));
            }

            let _ = scheme.whir_witness.prove(
                &mut merlin,
                vec![Cow::Borrowed(p2.as_slice())],
                vec![Cow::Owned(w2)],
                boxed_weights,
                Cow::Borrowed(&evaluations),
            );
        }
    }

    // Open the ext blinding commitment: prove `blinding_eval` is the evaluation
    // of the committed blinding vector (g flattened at offset 0) against the
    // sumcheck power covector. Sent after all base-witness opens (mirrored in
    // the verifier).
    {
        let blind_domain = 1usize << scheme.whir_blinding.initial_num_variables();
        let blinding_covector = OffsetCovector::new(blinding_weights, 0, blind_domain);
        let _ = scheme.whir_blinding.prove(
            &mut merlin,
            vec![Cow::Borrowed(blinding_state.vector.as_slice())],
            vec![Cow::Owned(blinding_state.witness)],
            vec![Box::new(blinding_covector) as Box<dyn LinearForm<Ext<P>>>],
            Cow::Borrowed(&[blinding_eval]),
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

pub fn compute_blinding_coefficients_for_round<F: Field>(
    g_univariates: &[[F; 4]],
    compute_for: usize,
    alphas: &[F],
) -> [F; 4] {
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
    let mut prefix_sum = F::zero();
    for i in 0..compute_for {
        prefix_sum += eval_cubic_poly(g_univariates[i], alphas[i]);
    }

    // s = Σ_{i>r}(g_i(0) + g_i(1))
    let mut suffix_sum = F::zero();
    for g_coeffs in g_univariates.iter().skip(compute_for + 1) {
        suffix_sum += eval_cubic_poly(*g_coeffs, F::zero()) + eval_cubic_poly(*g_coeffs, F::one());
    }

    let two = F::one() + F::one();
    let mut prefix_multiplier = F::one();
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
        return [value, F::zero(), F::zero(), F::zero()];
    }

    [
        prefix_multiplier * coefficient_for_current_index[0] + constant_term_from_other_items,
        prefix_multiplier * coefficient_for_current_index[1],
        prefix_multiplier * coefficient_for_current_index[2],
        prefix_multiplier * coefficient_for_current_index[3],
    ]
}

pub fn sum_over_hypercube<F: Field>(g_univariates: &[[F; 4]]) -> F {
    let fixed_variables: &[F] = &[];
    let polynomial_coefficient =
        compute_blinding_coefficients_for_round(g_univariates, 0, fixed_variables);

    eval_cubic_poly(polynomial_coefficient, F::zero())
        + eval_cubic_poly(polynomial_coefficient, F::one())
}

fn generate_blinding_univariates<F: Field>(m_0: usize) -> Vec<[F; 4]> {
    let mut rng = ark_std::rand::thread_rng();
    (0..m_0)
        .map(|_| std::array::from_fn(|_| F::rand(&mut rng)))
        .collect()
}

#[inline]
pub fn pad_to_pow2_len_min2<F: Field>(v: &mut Vec<F>) {
    let target = v.len().max(2).next_power_of_two();
    if v.len() < target {
        v.resize(target, F::zero());
    }
}

#[instrument(skip_all)]
pub fn run_zk_sumcheck_prover<F: Field + Codec, S: DuplexSpongeInterface<U = u8>>(
    mut a: Vec<F>,
    mut b: Vec<F>,
    mut c: Vec<F>,
    merlin: &mut ProverState<S>,
    m_0: usize,
    blinding_polynomial: &[[F; 4]],
    w1_polynomial: &[F],
    blinding_offset: usize,
) -> (Vec<F>, F) {
    let r: Vec<F> = merlin.verifier_message_vec(m_0);
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r, 1 << r.len());

    pad_to_pow2_len_min2(&mut a);
    pad_to_pow2_len_min2(&mut b);
    pad_to_pow2_len_min2(&mut c);
    pad_to_pow2_len_min2(&mut eq);

    let mut alpha = Vec::<F>::with_capacity(m_0);

    let sum_g_reduce = sum_over_hypercube(blinding_polynomial);

    merlin.prover_message(&sum_g_reduce);

    let rho: F = merlin.verifier_message();

    // Prove that sum of F + ρ·G over the boolean hypercube equals ρ·Σ(G).
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

        let g_poly =
            compute_blinding_coefficients_for_round(blinding_polynomial, idx, alpha.as_slice());

        let mut combined_hhat_i_coeffs = [F::zero(); 4];

        combined_hhat_i_coeffs[0] = hhat_i_at_0 + rho * g_poly[0];

        let g_at_minus_one = g_poly[0] - g_poly[1] + g_poly[2] - g_poly[3];
        let combined_at_em1 = hhat_i_at_em1 + rho * g_at_minus_one;

        let two = F::one() + F::one();
        combined_hhat_i_coeffs[2] = (saved_val_for_sumcheck_equality_assertion + combined_at_em1
            - combined_hhat_i_coeffs[0]
            - combined_hhat_i_coeffs[0]
            - combined_hhat_i_coeffs[0])
            / two;

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
        let alpha_i: F = merlin.verifier_message();
        alpha.push(alpha_i);

        fold = Some(alpha_i);

        saved_val_for_sumcheck_equality_assertion =
            eval_cubic_poly(combined_hhat_i_coeffs, alpha_i);
    }
    drop((a, b, c, eq));

    let weight_vec = expand_powers::<4, _>(alpha.as_slice());
    let blinding_eval = dot(
        &weight_vec,
        &w1_polynomial[blinding_offset..blinding_offset + weight_vec.len()],
    );
    merlin.prover_message(&blinding_eval);

    (alpha, blinding_eval)
}

fn create_weights_and_evaluations<const N: usize, M: Embedding>(
    embedding: &M,
    m: usize,
    polynomial: &[M::Source],
    alphas: [Vec<M::Target>; N],
) -> (Vec<PrefixCovector<M::Target>>, Vec<M::Target>) {
    let domain_size = 1usize << m;

    let mut weights = Vec::with_capacity(N);
    let mut evals = Vec::with_capacity(N);

    for mut w in alphas {
        let base_len = w.len().next_power_of_two().max(2);
        w.resize(base_len, M::Target::zero());

        evals.push(mixed_dot(embedding, &w, &polynomial[..base_len]));
        weights.push(PrefixCovector::new(w, domain_size));
    }

    (weights, evals)
}

fn compute_evaluations<M: Embedding>(
    embedding: &M,
    weights: &[PrefixCovector<M::Target>],
    polynomial: &[M::Source],
) -> Vec<M::Target> {
    weights
        .iter()
        .map(|w| mixed_dot(embedding, w.vector(), &polynomial[..w.vector().len()]))
        .collect()
}

fn compute_public_weight_evaluation<M: Embedding>(
    embedding: &M,
    weights: &mut Vec<PrefixCovector<M::Target>>,
    polynomial: &[M::Source],
    public_weights: PrefixCovector<M::Target>,
) -> M::Target {
    let n = public_weights.vector().len();
    let eval = mixed_dot(embedding, public_weights.vector(), &polynomial[..n]);
    weights.insert(0, public_weights);
    eval
}

fn get_public_weights<F: Field + Codec, S: DuplexSpongeInterface<U = u8>>(
    public_inputs_hash: F,
    public_inputs_len: usize,
    merlin: &mut ProverState<S>,
    m: usize,
) -> (F, PrefixCovector<F>) {
    merlin.prover_message(&public_inputs_hash);

    let x: F = merlin.verifier_message();

    (x, make_public_weight(x, public_inputs_len, m))
}
