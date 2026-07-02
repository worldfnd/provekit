use {
    anyhow::{ensure, Result},
    ark_ff::UniformRand,
    ark_std::{One, Zero},
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
            HALF,
        },
        FieldElement, PrefixCovector, PublicInputs, TranscriptSponge, WhirR1CSProof,
        WhirR1CSScheme, R1CS,
    },
    std::borrow::Cow,
    tracing::instrument,
    whir::{
        algebra::{dot, linear_form::LinearForm},
        protocols::whir_zk::Witness as WhirZkWitness,
        transcript::{ProverState, VerifierMessage},
    },
};
#[cfg(not(target_arch = "wasm32"))]
use {
    mavros_artifacts::{ConstraintsLayout, WitnessLayout},
    mavros_vm::interpreter::Phase1Result,
};

pub struct BlindingState {
    pub polynomial: Vec<[FieldElement; 4]>,
    pub offset:     usize,
}

pub struct WhirR1CSCommitment {
    pub witness:    WhirZkWitness<FieldElement>,
    pub polynomial: Vec<FieldElement>,
    pub blinding:   Option<BlindingState>,
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

    fn prove_noir(
        &self,
        merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        full_witness: Vec<FieldElement>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof>;

    #[cfg(not(target_arch = "wasm32"))]
    fn prove_mavros(
        &self,
        merlin: ProverState<TranscriptSponge>,
        phase1: Phase1Result,
        commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        ad_binary: &[u64],
    ) -> Result<WhirR1CSProof>;
}

impl WhirR1CSProver for WhirR1CSScheme {
    #[instrument(skip_all)]
    // Blinded commit function for the split witnesses w1 and w2
    // Also commits to the zk-WHIR 2.0 blinders.  
    fn commit(
        &self,
        merlin: &mut ProverState<TranscriptSponge>,
        num_witnesses: usize,
        num_constraints: usize,
        witness: Vec<FieldElement>,
        is_w1: bool, // w1 is the first round witness, before the logup challenges are drawn
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

        // We currently pad the witnesses to the same length 2^num_vars.
        let num_vars = self.whir_witness.num_witness_variables();
        let target_len = 1usize << num_vars;

        let mut padded_witness = pad_to_power_of_two(witness);
        if padded_witness.len() < target_len {
            padded_witness.resize(target_len, FieldElement::zero());
        }

        let blinding = if is_w1 {
            // Sample the blinders for the zerocheck
            let g = generate_blinding_univariates(self.m_0);
            // We write them in the range padded_witness[witness_size..] to avoid a separate commitment.
            let offset = witness_size;
            for (i, coeffs) in g.iter().enumerate() {
                for (j, &c) in coeffs.iter().enumerate() {
                    padded_witness[offset + i * 4 + j] = c;
                }
            }
            Some(BlindingState {
                polynomial: g,
                offset,
            })
        } else {
            None 
        };

        // zk-WHIR 2.0 commit of the blinded and padded witness.
        // Recall that this commits to padded_witness using the opening mask `msk` and 
        // the small multilinear blinders `g_1`,.., `g_m`, which are returned as 
        // the zk_witness
        let zk_witness = self.whir_witness.commit(merlin, &[&padded_witness]);

        Ok(WhirR1CSCommitment {
            witness: zk_witness,
            polynomial: padded_witness,
            // the blinders for the sumcheck
            blinding,
        })
    }

    #[instrument(skip_all)]
    // Build proof from the (randomized) R1CS witnesses and their commitments. 
    fn prove_noir(
        &self,
        mut merlin: ProverState<TranscriptSponge>,
        r1cs: R1CS,
        commitments: Vec<WhirR1CSCommitment>,
        full_witness: Vec<FieldElement>,
        public_inputs: &PublicInputs,
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        // compute image vectors a = A.w, b = B.w, c = C.w
        let (a, b, c) = calculate_witness_bounds(&r1cs, &full_witness);
        drop(full_witness);

        // the zero-check blinders are baked into the w1 commitment
        let blinding = commitments[0]
            .blinding
            .as_ref()
            .expect("c1 must carry blinding state");

        // Phase 1: run zero-check on a*b - c = 0 over the hypercube.
        // Reduces constraint satisfaction to evaluation claims of 
        //   v_A = a(alpha), v_B = b(alpha), v_C = c(alpha), 
        // and the blinders
        //   h_1(alpha_1), ..., h_m(alpha_m)
        // where alpha = (alpha_1,...,alpha_m) are theverifier randmoness 
        // collected over the zerocheck.
        // Concretely: it reduces the zero-check claim to the claim a claim on
        //    (a(alpha)*b(alpha) - c(alpha))*eq(r, alpha) + blinding_eval,
        // with
        //    blinding_eval = h(alpha_1) + ... + h(alpha_m). 
        let (alpha, blinding_eval) = run_zk_sumcheck_prover(
            a,
            b,
            c,
            &mut merlin,
            self.m_0,
            &blinding.polynomial,
            &commitments[0].polynomial,
            blinding.offset,
        );

        // Compute the inner product kernels for 
        //    m(alpha) = Sum_{.} M(alpha, .) w(.) = < eq( . , alpha) * M, w > 
        // for each M = A, B, C. 
        let (at, bt, ct) = transpose_r1cs_matrices(&r1cs);
        let alphas = multiply_transposed_by_eq_alpha(&at, &bt, &ct, &alpha, &r1cs);

        // we prove the blinding_eval via WHIR. Let us prepare the weights.
        let blinding_offset = blinding.offset;
        let blinding_weights = expand_powers::<4>(&alpha);
        
        // Phase 2: The WHIR proof of the three evaluation claims 
        //   v_M = < eq(alpha, . ) * M, w >,
        // M = A,B,C. Reduces correctness of these values to 
        // evaluation claims on 
        //   A(alpha, beta), B(alpha, beta), C(alpha, beta),
        // where beta are the WHIR folding randomnesses.
        prove_from_alphas(
            self,
            merlin,
            alphas,
            blinding_eval,
            blinding_offset,
            blinding_weights,
            commitments,
            public_inputs,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(skip_all)]
    fn prove_mavros(
        &self,
        mut merlin: ProverState<TranscriptSponge>,
        phase1: Phase1Result,
        commitments: Vec<WhirR1CSCommitment>,
        public_inputs: &PublicInputs,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        ad_binary: &[u64],
    ) -> Result<WhirR1CSProof> {
        ensure!(!commitments.is_empty(), "Need at least one commitment");

        let blinding = commitments[0]
            .blinding
            .as_ref()
            .expect("c1 must carry blinding state");

        let [a, b, c] = [phase1.out_a, phase1.out_b, phase1.out_c];
        let (alpha, blinding_eval) = run_zk_sumcheck_prover(
            a,
            b,
            c,
            &mut merlin,
            self.m_0,
            &blinding.polynomial,
            &commitments[0].polynomial,
            blinding.offset,
        );

        let eq_alpha =
            calculate_evaluations_over_boolean_hypercube_for_eq(&alpha, 1 << alpha.len());
        let (ad_a, ad_b, ad_c, _) = mavros_vm::interpreter::run_ad(
            ad_binary,
            &eq_alpha[..constraints_layout.algebraic_size],
            witness_layout,
            constraints_layout,
        );
        // what is this?
        let alphas = [ad_a, ad_b, ad_c];

        let blinding_offset = blinding.offset;
        let blinding_weights = expand_powers::<4>(&alpha);

        prove_from_alphas(
            self,
            merlin,
            alphas,
            blinding_eval,
            blinding_offset,
            blinding_weights,
            commitments,
            public_inputs,
        )
    }
}


// The reduction from claims on the image polynomials a(alpha), b(alpha), c(alpha) to 
// claims on the circuit polys M(alpha, beta), M = A,B,C
// This part is performed by WHIR.
// In the two-round (split-witness) case, two WHIR proofs are provided.
#[instrument(skip_all)]
fn prove_from_alphas(
    scheme: &WhirR1CSScheme,
    mut merlin: ProverState<TranscriptSponge>,
    alphas: [Vec<FieldElement>; 3],
    blinding_eval: FieldElement,
    blinding_offset: usize,
    blinding_weights: Vec<FieldElement>,
    commitments: Vec<WhirR1CSCommitment>,
    public_inputs: &PublicInputs,
) -> Result<WhirR1CSProof> {
    let public_inputs_hash = public_inputs.hash(scheme.hash_config);
    let public_inputs_len = public_inputs.len();

    let is_single = commitments.len() == 1;
    // We prove the public inputs, including the Fiat-Shamir challenge, to be at the
    // expected positions of w1 and w2, respectively. 
    // For batching their values we draw a verifier challenge `x`, and directly built
    // a covector `public_weight` from `x`. 
    // QUESTION: is this done for efficiency reasons?
    let (x, public_weight) =
        get_public_weights(public_inputs_hash, public_inputs_len, &mut merlin, scheme.m);

    let domain_size = 1usize << scheme.m;

    if is_single {
        // Single commitment path
        let commitment = commitments
            .into_iter()
            .next()
            .expect("single-commitment path requires at least one commitment");

        // Prep. for WHIR: turn the inner product kernels into covectors
        // claim and absorb the inner product values a(alpha), b(alpha), c(alpha)
        // COMMENT: shouldn't be these claims already served in the last round of the zero-check?
        let (mut weights, evals) =
            create_weights_and_evaluations::<3>(scheme.m, &commitment.polynomial, alphas);

        for eval in &evals {
            merlin.prover_message(eval);
        }

        if public_inputs_len > 0 {
            // compute the random linear combination of the public inputs
            let public_eval = compute_public_weight_evaluation(
                &mut weights,
                &commitment.polynomial,
                public_weight,
            );
            // COMMENT: there is no reason to absorb, since public_eval depends on public data only
            // (the expected public inputs and `x`)
            merlin.prover_message(&public_eval);
        }

        // QUESTION: Why do we recompute all inner products? 
        let mut evaluations = compute_evaluations(&weights, &commitment.polynomial);
        evaluations.push(blinding_eval);

        let blinding_covector = OffsetCovector::new(blinding_weights, blinding_offset, domain_size);

        let mut boxed_weights: Vec<Box<dyn LinearForm<FieldElement>>> = weights
            .into_iter()
            .map(|w| Box::new(w) as Box<dyn LinearForm<FieldElement>>)
            .collect();
        boxed_weights.push(Box::new(blinding_covector));

        let _ = scheme.whir_witness.prove(
            &mut merlin,
            vec![Cow::Borrowed(commitment.polynomial.as_slice())],
            commitment.witness,
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

        // split the inner product kernels into two, according to the sizes of the round witnesses 
        let (alphas_1, alphas_2): (Vec<_>, Vec<_>) = alphas
            .into_iter()
            .map(|mut v| {
                let v2 = v.split_off(scheme.w1_size);
                (v, v2)
            })
            .unzip();

        let alphas_1: [Vec<FieldElement>; 3] = alphas_1
            .try_into()
            .expect("alphas_1 must have exactly 3 elements");
        let alphas_2: [Vec<FieldElement>; 3] = alphas_2
            .try_into()
            .expect("alphas_2 must have exactly 3 elements");

        // claim the values of the splitted inner products
        let evals_1 = compute_alpha_evals(&c1.polynomial, &alphas_1);
        let evals_2 = compute_alpha_evals(&c2.polynomial, &alphas_2);
        for eval in &evals_1 {
            merlin.prover_message(eval);
        }
        for eval in &evals_2 {
            merlin.prover_message(eval);
        }

        // We use WHIR to prove that w1 has the public inputs at the expected positions.
        // That is, we take inner product with the random co-vector `[1, x, ..., x^{public_input_len}, 0,...,0]`
        // into account.
        let public_1 = if public_inputs_len > 0 {
            let p1 = compute_public_eval(x, public_inputs_len, &c1.polynomial);
            merlin.prover_message(&p1);
            Some(p1)
        } else {
            None
        };

        // We use WHIR to prove that w2 contains the correct Fiat-Shamir challenge values at the expected positions.
        // For this we may reuse challenge `x` and take the kernel `[1, x, ..., x^{num_chal - 1}]` placed at the 
        // positions of the challenge input. 
        let challenge_eval = if !scheme.challenge_offsets.is_empty() {
            let ce = compute_challenge_eval(x, &scheme.challenge_offsets, &c2.polynomial);
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
            let mut evaluations: Vec<FieldElement> = Vec::new();
            if let Some(pe) = public_1 {
                weights.insert(0, make_public_weight(x, public_inputs_len, scheme.m));
                evaluations.push(pe);
            }
            evaluations.extend_from_slice(&evals_1);
            evaluations.push(blinding_eval);

            let blinding_covector =
                OffsetCovector::new(blinding_weights, blinding_offset, domain_size);

            let mut boxed_weights: Vec<Box<dyn LinearForm<FieldElement>>> = weights
                .into_iter()
                .map(|w| Box::new(w) as Box<dyn LinearForm<FieldElement>>)
                .collect();
            boxed_weights.push(Box::new(blinding_covector));

            // run WHIR on the first round witness. 
            let _ = scheme.whir_witness.prove(
                &mut merlin,
                vec![Cow::Borrowed(p1.as_slice())],
                w1,
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
            let mut evaluations: Vec<FieldElement> = evals_2;

            let mut boxed_weights: Vec<Box<dyn LinearForm<FieldElement>>> = weights
                .into_iter()
                .map(|w| Box::new(w) as Box<dyn LinearForm<FieldElement>>)
                .collect();

            if let Some(ce) = challenge_eval {
                let cw = make_challenge_weight(x, &scheme.challenge_offsets, scheme.m);
                evaluations.push(ce);
                boxed_weights.push(Box::new(cw));
            }

            // run WHIR on the second round witness
            let _ = scheme.whir_witness.prove(
                &mut merlin,
                vec![Cow::Borrowed(p2.as_slice())],
                w2,
                boxed_weights,
                Cow::Borrowed(&evaluations),
            );
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



// Computes the coefficient-wise contribution of the multivariate
// sumcheck blinder
//    g_1(x_1) + g_2(x_2) + ...  + g_m(x_m)
// 
pub fn compute_blinding_coefficients_for_round(
    g_univariates: &[[FieldElement; 4]],
    compute_for: usize, // shouldn't be that clear from how many alphas are given?
    alphas: &[FieldElement],
) -> [FieldElement; 4] {
    let mut compute_for = compute_for;
    let n = g_univariates.len();
    assert!(compute_for <= n);
    assert_eq!(alphas.len(), compute_for);
    let mut all_fixed = false;
    // a bit weird treatment of the edge case
    if compute_for == n {
        all_fixed = true;
        compute_for = n - 1;
    }

    // r = compute_for + 1
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
    // prefix_multiplier = 2^{n - 1 - (r-1)}
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

fn generate_blinding_univariates(m_0: usize) -> Vec<[FieldElement; 4]> {
    let mut rng = ark_std::rand::thread_rng();
    (0..m_0)
        .map(|_| std::array::from_fn(|_| FieldElement::rand(&mut rng)))
        .collect()
}

#[inline]
pub fn pad_to_pow2_len_min2(v: &mut Vec<FieldElement>) {
    let target = v.len().max(2).next_power_of_two();
    if v.len() < target {
        v.resize(target, FieldElement::zero());
    }
}




/// Run the R1CS zerocheck a * b - c = 0 over the hypercube of dimension m_0,
/// using the `m_0` univariate blinder polynomials h_1(X), .. h_m(X) of degree 3 
/// for zero-knowledge.
/// Returns the sumcheck challenges
///     alpha_1,.., alpha_{m_0}, 
/// and 
///     blinding_eval = h_1(alpha_1) + ..  + h_{m_0}(alpha_{m_0}).
#[instrument(skip_all)]
pub fn run_zk_sumcheck_prover(
    mut a: Vec<FieldElement>,
    mut b: Vec<FieldElement>,
    mut c: Vec<FieldElement>,
    merlin: &mut ProverState<TranscriptSponge>,
    m_0: usize,
    // The sumcheck is of degree 3, hence each blinding poly is defined by 4 coefficients.
    // should consist of m_0 many such blinders
    blinding_polynomial: &[[FieldElement; 4]],
    // COMMENT: serving w_1 and the blinding_offset is not strictly needed, see below.
    w1_polynomial: &[FieldElement],
    blinding_offset: usize,
) -> (Vec<FieldElement>, FieldElement) {
    // sample random Lagrangian eq(r, . ) in order to reduce to inner product sumcheck.
    let r: Vec<FieldElement> = merlin.verifier_message_vec(m_0);
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r, 1 << r.len());

    pad_to_pow2_len_min2(&mut a);
    pad_to_pow2_len_min2(&mut b);
    pad_to_pow2_len_min2(&mut c);
    pad_to_pow2_len_min2(&mut eq);

    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);

    let sum_g_reduce = sum_over_hypercube(blinding_polynomial);

    merlin.prover_message(&sum_g_reduce);

    let rho: FieldElement = merlin.verifier_message();

    // Prove that sum of F + ρ·G over the boolean hypercube equals ρ·Σ(G).
    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_reduce;

    let mut fold = None;

    for idx in 0..m_0 {
        // We compute the sumcheck poly 
        //   h(X) =  Sum_{.} (a(X, .) * b(X, .) - c(X, .)) * eq(X, . ) 
        // at the 3 points X in {0, -1, infty}. 
        // Why not four points rests on the specific form of the sumcheck poly
        //    Sum_{.} (a(X,.)*b(X,.) - c(X,.)) * eq(X,r1)  * eq(. ,r2..)
        //     = eq(X,r1) * Sum_{.} (a(X,.)*b(X,.) - c(X,.)) * eq(. ,r2..)
        //     = eq(X,r1) * q(X) 
        //  with q(X) is quadratic. Thus three points suffice.
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut a, &mut b, &mut c, &mut eq], fold, |[a, b, c, eq]| {
                // any linear extension in the first variable
                //
                //       f(X, . ) = (1-X) * f(0, . ) + X * f(1, . ) 
                // 
                // at X  = 0: just take the first halves 
                let f0 = eq.0 * (a.0 * b.0 - c.0);
                // at X  = -1: 
                // why not at X = + 1? that would be only eq.1 * (a.1 * b.1 - c.1);
                let f_em1 = (eq.0 + eq.0 - eq.1)
                    * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
                // at X = infty: this gives us the coeff of X 
                let f_inf = (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);

                [f0, f_em1, f_inf]
            });
        // The first half stores the folding, using fold.
        if fold.is_some() {
            a.truncate(a.len() / 2);
            b.truncate(b.len() / 2);
            c.truncate(c.len() / 2);
            eq.truncate(eq.len() / 2);
        }

        // compute the blinder of the round, coefficient-wise
        let g_poly =
            compute_blinding_coefficients_for_round(blinding_polynomial, idx, alpha.as_slice());

        let mut combined_hhat_i_coeffs = [FieldElement::zero(); 4];

        // with the linear function eq(X,r) = 1 - X + r (2 X - 1) = (2r - 1) X + 1 - r 
        // 
        // h(X) = ((2r1 - 1) X + 1 - r1)  * (c_2 X^2 + c_1 X + c_0)
        //      = d_3 X^3 + d_2 X^2 + d_1 X + d_0
        // 
        // h(0) = - r1 * c_0 = d_0
        // h(-1) = -(2 - 3r1) * (c_2 - c_1 + c_0)
        // h(infty) = (2r1 - 1) * c_2 = d_3 
        // TODO: further elaboration of the formulas below.

        combined_hhat_i_coeffs[0] = hhat_i_at_0 + rho * g_poly[0];

        let g_at_minus_one = g_poly[0] - g_poly[1] + g_poly[2] - g_poly[3];
        let combined_at_em1 = hhat_i_at_em1 + rho * g_at_minus_one;

        // d_2 = 1/2 (h(0) + h(1) + h(-1) + g(-1) )
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

        // absorb the blinded sumcheck polynomial 
        for coeff in &combined_hhat_i_coeffs {
            merlin.prover_message(coeff);
        }
        // draw verifier randomness 
        let alpha_i: FieldElement = merlin.verifier_message();
        alpha.push(alpha_i);

        fold = Some(alpha_i);

        // the new sumcheck claim
        saved_val_for_sumcheck_equality_assertion =
            eval_cubic_poly(combined_hhat_i_coeffs, alpha_i);
    }
    drop((a, b, c, eq));

    // after last sumcheck round, we reveal the value of
    //   (a(alpha)*b(alpha) - c(alpha)) eq(alpha,r) + h_1(alpha_1) + .. + h_m(alpha_m)
    // and we return the sum of the blinder values. 
    // COMMENT: Alternatively we could derive blinding_eval from the blinder polynomials.
    // This would eleminate passing w_1 to the function.
    let weight_vec = expand_powers::<4>(alpha.as_slice());
    let blinding_eval = dot(
        &weight_vec,
        &w1_polynomial[blinding_offset..blinding_offset + weight_vec.len()],
    );
    merlin.prover_message(&blinding_eval);

    (alpha, blinding_eval)
}


// Helper function to turn inner product kernels `alphas`
// into twoadic length covectors.
// Recomputes the values of the inner product with `polynomial`
fn create_weights_and_evaluations<const N: usize>(
    m: usize,
    polynomial: &[FieldElement],
    alphas: [Vec<FieldElement>; N],
) -> (Vec<PrefixCovector>, Vec<FieldElement>) {
    let domain_size = 1usize << m;

    let mut weights = Vec::with_capacity(N);
    let mut evals = Vec::with_capacity(N);

    for mut w in alphas {
        // zero-pad inner product kernel to next power of two
        let base_len = w.len().next_power_of_two().max(2);
        w.resize(base_len, FieldElement::zero());

        // COMMENT: why recompute the value of the inner product?
        evals.push(dot(&w, &polynomial[..base_len]));
        // turn inner product kernel into a covector
        weights.push(PrefixCovector::new(w, domain_size));
    }

    (weights, evals)
}

// inner product of a covector with the polynomial
fn compute_evaluations(
    weights: &[PrefixCovector],
    polynomial: &[FieldElement],
) -> Vec<FieldElement> {
    weights
        .iter()
        .map(|w| dot(w.vector(), &polynomial[..w.vector().len()]))
        .collect()
}

fn compute_public_weight_evaluation(
    weights: &mut Vec<PrefixCovector>,
    polynomial: &[FieldElement],
    public_weights: PrefixCovector,
) -> FieldElement {
    let n = public_weights.vector().len();
    let eval = dot(public_weights.vector(), &polynomial[..n]);
    weights.insert(0, public_weights);
    eval
}

// samples the input randomness and builds its covector from it.
fn get_public_weights(
    public_inputs_hash: FieldElement,
    public_inputs_len: usize,
    merlin: &mut ProverState<TranscriptSponge>,
    m: usize,
) -> (FieldElement, PrefixCovector) {
    merlin.prover_message(&public_inputs_hash);

    let x: FieldElement = merlin.verifier_message();

    (x, make_public_weight(x, public_inputs_len, m))
}
