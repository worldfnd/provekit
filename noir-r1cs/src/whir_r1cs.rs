use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        utils::{
            next_power_of_two, pad_to_power_of_two, serde_ark, serde_hex,
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq,
                calculate_external_row_of_r1cs_matrices, calculate_witness_bounds, eval_qubic_poly,
                sumcheck_fold_map_reduce, SumcheckIOPattern,
            },
            zk_utils::{
                create_masked_polynomial, generate_mask, generate_random_multilinear_polynomial,
            },
            HALF,
        },
        FieldElement, R1CS,
    },
    anyhow::{ensure, Context, Result},
    ark_ff::UniformRand,
    ark_std::{One, Zero},
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
        DomainSeparator, ProverState, VerifierState,
    },
    std::fmt::{Debug, Formatter},
    tracing::{info, instrument, warn},
    whir::{
        parameters::{
            default_max_pow, FoldingFactor,
            MultivariateParameters as GenericMultivariateParameters,
            ProtocolParameters as GenericProtocolParameters, SoundnessType,
        },
        poly_utils::evals::EvaluationsList,
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader, CommitmentWriter, Witness},
            domainsep::WhirDomainSeparator,
            parameters::WhirConfig as GenericWhirConfig,
            prover::Prover,
            statement::{Statement, Weights},
            verifier::Verifier,
        },
    },
};

pub type MultivariateParameters = GenericMultivariateParameters<FieldElement>;
pub type ProtocolParameters = GenericProtocolParameters<SkyscraperMerkleConfig, SkyscraperPoW>;
pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;
pub type IOPattern = DomainSeparator<SkyscraperSponge, FieldElement>;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m:           usize,
    pub m_0:         usize,
    pub whir_config: WhirConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,

    // TODO: Derive from transcript
    #[serde(with = "serde_ark")]
    pub whir_query_answer_sums: ([FieldElement; 3], [FieldElement; 3]),
}

pub struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

impl WhirR1CSScheme {
    pub fn new_for_r1cs(r1cs: &R1CS) -> Self {
        Self::new_for_size(r1cs.num_witnesses(), r1cs.num_constraints())
    }

    pub fn new_for_size(witnesses: usize, constraints: usize) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
        let m = next_power_of_two(witnesses);

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m_0 = next_power_of_two(constraints);

        // Whir parameters
        let mv_params = MultivariateParameters::new(m + 1);
        let whir_params = ProtocolParameters {
            initial_statement:     true,
            security_level:        128,
            pow_bits:              default_max_pow(m + 1, 1),
            folding_factor:        FoldingFactor::Constant(4),
            leaf_hash_params:      (),
            two_to_one_params:     (),
            soundness_type:        SoundnessType::ConjectureList,
            _pow_parameters:       Default::default(),
            starting_log_inv_rate: 1,
            batch_size:            2,
        };
        let whir_config = WhirConfig::new(mv_params, whir_params);

        Self {
            m: m + 1,
            m_0,
            whir_config,
        }
    }

    pub fn commit_to_witness(
        &self,
        witness_polynomial_evals: EvaluationsList<FieldElement>,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> (
        Witness<FieldElement, SkyscraperMerkleConfig>,
        EvaluationsList<FieldElement>,
        EvaluationsList<FieldElement>,
    ) {
        let mask = generate_mask(witness_polynomial_evals.evals().len());
        let masked_polynomial = create_masked_polynomial(&witness_polynomial_evals, &mask);

        let masked_polynomial_coeff = masked_polynomial.to_coeffs();

        let random_polynomial_eval = generate_random_multilinear_polynomial(self.m);
        let random_polynomial_coeff = random_polynomial_eval.to_coeffs();

        let committer = CommitmentWriter::new(self.whir_config.clone());
        let witness_new = committer
            .commit_batch(merlin, &[
                masked_polynomial_coeff.clone(),
                random_polynomial_coeff.clone(),
            ])
            .expect("WHIR prover failed to commit");

        (witness_new, masked_polynomial, random_polynomial_eval)
    }

    #[instrument(skip_all)]
    pub fn prove(&self, r1cs: &R1CS, witness: Vec<FieldElement>) -> Result<WhirR1CSProof> {
        ensure!(
            witness.len() == r1cs.num_witnesses(),
            "Unexpected witness length for R1CS instance"
        );
        ensure!(
            r1cs.num_witnesses() <= 1 << self.m,
            "R1CS witness length exceeds scheme capacity"
        );
        ensure!(
            r1cs.num_constraints() <= 1 << self.m_0,
            "R1CS constraints exceed scheme capacity"
        );

        // Set up transcript
        let io: IOPattern = create_io_pattern(self.m_0, &self.whir_config);
        let mut merlin = io.to_prover_state();
        let z = pad_to_power_of_two(witness.clone());
        let witness_polynomial_evals = EvaluationsList::new(z.clone());

        let (witness_new, masked_polynomial, random_polynomial) =
            self.commit_to_witness(witness_polynomial_evals.clone(), &mut merlin);

        // First round of sumcheck to reduce R1CS to a batch weighted evaluation of the
        // witness
        let (merlin, alpha) = run_zk_sumcheck_prover(r1cs, &witness, merlin, self.m_0);

        // Compute weights from R1CS instance
        let alphas = calculate_external_row_of_r1cs_matrices(&alpha, r1cs);

        // Compute WHIR weighted batch opening proof
        let (merlin, whir_query_answer_sums) = run_zk_whir_pcs_prover(
            witness_new,
            masked_polynomial,
            random_polynomial,
            &self.whir_config,
            merlin,
            self.m,
            alphas,
        );

        let transcript = merlin.narg_string().to_vec();

        Ok(WhirR1CSProof {
            transcript,
            whir_query_answer_sums,
        })
    }

    #[instrument(skip_all)]
    #[allow(unused)] // TODO: Fix implementation
    pub fn verify(&self, proof: &WhirR1CSProof) -> Result<()> {
        // Set up transcript
        let io = create_io_pattern(self.m_0, &self.whir_config);
        let mut arthur = io.to_verifier_state(&proof.transcript);

        let commitment_reader = CommitmentReader::new(&self.whir_config);
        let parsed_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

        // Compute statement verifier
        let mut statement_verifier = Statement::<FieldElement>::new(self.m);
        for i in 0..proof.whir_query_answer_sums.0.len() {
            let claimed_sum = proof.whir_query_answer_sums.0[i]
                + proof.whir_query_answer_sums.1[i] * parsed_commitment.batching_randomness;
            statement_verifier.add_constraint(
                Weights::linear(EvaluationsList::new(vec![
                    FieldElement::zero();
                    1 << self.m
                ])),
                claimed_sum,
            );
        }

        let data_from_sumcheck_verifier =
            run_sumcheck_verifier(&mut arthur, self.m_0).context("while verifying sumcheck")?;

        run_whir_pcs_verifier(
            &mut arthur,
            &parsed_commitment,
            &self.whir_config,
            &statement_verifier,
        )
        .context("while verifying WHIR proof")?;

        // Check the Spartan sumcheck relation.
        ensure!(
            data_from_sumcheck_verifier.last_sumcheck_val
                == (proof.whir_query_answer_sums.0[0] * proof.whir_query_answer_sums.0[1]
                    - proof.whir_query_answer_sums.0[2])
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        // TODO: Verify evaluation of sparse matrices in random point.

        Ok(())
    }
}

// TODO: Implement Debug for WhirConfig and derive.
impl Debug for WhirR1CSScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhirR1CSScheme")
            .field("m", &self.m)
            .field("m_0", &self.m_0)
            .finish()
    }
}

pub fn compute_g_poly(
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
        prefix_sum += eval_qubic_poly(&g_univariates[i], &alphas[i]);
    }

    // s = Σ_{i>r}(g_i(0) + g_i(1))
    let mut suffix_sum = FieldElement::zero();
    for g_coeffs in g_univariates.iter().skip(compute_for + 1) {
        suffix_sum += eval_qubic_poly(g_coeffs, &FieldElement::zero())
            + eval_qubic_poly(g_coeffs, &FieldElement::one());
    }

    let two = FieldElement::one() + FieldElement::one();
    let mut prefix_multiplier = FieldElement::one();
    for _ in 0..(n - 1 - compute_for) {
        prefix_multiplier = prefix_multiplier + prefix_multiplier;
    }
    let suffix_multiplier: ark_ff::Fp<
        ark_ff::MontBackend<whir::crypto::fields::BN254Config, 4>,
        4,
    > = prefix_multiplier / two;

    let constant_term_from_other_items =
        prefix_multiplier * prefix_sum + suffix_multiplier * suffix_sum;

    let coefficient_for_current_index = &g_univariates[compute_for];

    if all_fixed {
        let value = eval_qubic_poly(
            &[
                prefix_multiplier * coefficient_for_current_index[0]
                    + constant_term_from_other_items,
                prefix_multiplier * coefficient_for_current_index[1],
                prefix_multiplier * coefficient_for_current_index[2],
                prefix_multiplier * coefficient_for_current_index[3],
            ],
            &alphas[compute_for],
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
    let alphas: &[FieldElement] = &[];
    let h0 = compute_g_poly(g_univariates, 0, alphas);

    eval_qubic_poly(&h0, &FieldElement::zero()) + eval_qubic_poly(&h0, &FieldElement::one())
}

#[instrument(skip_all)]
pub fn run_zk_sumcheck_prover(
    r1cs: &R1CS,
    z: &[FieldElement],
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> (
    ProverState<SkyscraperSponge, FieldElement>,
    Vec<FieldElement>,
) {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    merlin
        .fill_challenge_scalars(&mut r)
        .expect("Failed to extract challenge scalars from Merlin");

    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    let ((mut a, mut b, mut c), mut eq) = rayon::join(
        || calculate_witness_bounds(r1cs, z),
        || calculate_evaluations_over_boolean_hypercube_for_eq(&r),
    );

    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);

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

    let sum_g_reduce = sum_over_hypercube(g_univariates.as_slice());

    let _ = merlin.add_scalars(&[sum_g_reduce]);

    let mut rho_buf = [FieldElement::zero()];
    let _ = merlin.fill_challenge_scalars(&mut rho_buf);
    let rho = rho_buf[0];

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

        let g_poly = compute_g_poly(g_univariates.as_slice(), idx, alpha.as_slice());

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
            eval_qubic_poly(&combined_hhat_i_coeffs, &alpha_i);
    }

    let g_alpha_eval = compute_g_poly(g_univariates.as_slice(), alpha.len(), alpha.as_slice())[0];
    let _ = merlin.add_scalars(&[g_alpha_eval]);

    (merlin, alpha)
}


#[instrument(skip_all)]
pub fn run_zk_whir_pcs_prover(
    witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    f_polynomial: EvaluationsList<FieldElement>,
    g_polynomial: EvaluationsList<FieldElement>,
    params: &WhirConfig,
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m: usize,
    alphas: [Vec<FieldElement>; 3],
) -> (
    ProverState<SkyscraperSponge, FieldElement>,
    ([FieldElement; 3], [FieldElement; 3]),
) {
    info!("WHIR Parameters: {params}");

    if !params.check_pow_bits() {
        warn!("More PoW bits required than specified.");
    }

    let mut statement = Statement::<FieldElement>::new(m);

    let pairs: [(FieldElement, FieldElement); 3] = alphas.map(|alpha| {
        let mut a = pad_to_power_of_two(alpha);
        a.resize(a.len() * 2, FieldElement::zero());

        let weight = Weights::linear(EvaluationsList::new(a));
        let f = weight.weighted_sum(&f_polynomial);
        let g = weight.weighted_sum(&g_polynomial);
        // add the combined constraint
        statement.add_constraint(weight, f + witness.batching_randomness * g);
        (f, g)
    });

    let f_sums = pairs.map(|(f, _)| f);
    let g_sums = pairs.map(|(_, g)| g);

    let prover = Prover(params.clone());
    prover
        .prove(&mut merlin, statement, witness)
        .expect("WHIR prover failed to generate a proof");

    (merlin, (f_sums, g_sums))
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> Result<DataFromSumcheckVerifier> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

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
        let hhat_i_at_zero = eval_qubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_qubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i, &alpha_i[0]);
    }

    let mut g_alpha_eval_buf = [FieldElement::zero()];
    arthur.fill_next_scalars(&mut g_alpha_eval_buf)?;
    let g_alpha = g_alpha_eval_buf[0];

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * g_alpha;

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
) -> Result<()> {
    let verifier = Verifier::new(params);

    verifier
        .verify(arthur, parsed_commitment, statement_verifier)
        .context("while verifying WHIR")?;

    Ok(())
}

#[instrument(skip_all)]
pub fn create_io_pattern(m_0: usize, whir_params: &WhirConfig) -> IOPattern {
    IOPattern::new("🌪️")
        .commit_statement(whir_params)
        .add_rand(m_0)
        .add_sumcheck_polynomials(m_0)
        .add_whir_proof(whir_params)
}
