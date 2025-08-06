use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        spark::{prove_spark, verify_spark, SparkIOPattern},
        utils::{
            next_power_of_two, pad_to_power_of_two, serde_hex,
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq,
                calculate_external_row_of_r1cs_matrices, calculate_witness_bounds, eval_cubic_poly,
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
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader, CommitmentWriter, Witness},
            domainsep::WhirDomainSeparator,
            parameters::WhirConfig as GenericWhirConfig,
            prover::Prover,
            statement::{Statement, Weights},
            utils::{HintDeserialize, HintSerialize},
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
    pub m: usize,
    pub m_0: usize,
    pub a_num_terms: usize,
    pub whir_witness: WhirConfig,
    pub whir_config_row: WhirConfig,
    pub whir_config_col: WhirConfig,
    pub whir_config_a_num_terms: WhirConfig,
    pub whir_for_hiding_spartan: WhirConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,
}

pub struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

impl WhirR1CSScheme {
    pub fn new_for_r1cs(r1cs: &R1CS) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
        let m = next_power_of_two(r1cs.num_witnesses());

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m_0 = next_power_of_two(r1cs.num_constraints());

        // Whir parameters
        Self {
            m: m + 1,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            whir_config_row: Self::new_whir_config_for_size(m_0, 1),
            whir_config_col: Self::new_whir_config_for_size(m, 1),
            whir_witness: Self::new_whir_config_for_size(m + 1, 2),
            whir_config_a_num_terms: Self::new_whir_config_for_size(
                next_power_of_two(r1cs.a().matrix.num_entries()),
                1,
            ),
            whir_for_hiding_spartan: Self::new_whir_config_for_size(
                next_power_of_two(4 * m_0) + 1,
                2,
            ),
        }
    }

    pub fn new_whir_config_for_size(num_variables: usize, batch_size: usize) -> WhirConfig {
        let mv_params = MultivariateParameters::new(num_variables);
        let whir_params = ProtocolParameters {
            initial_statement: true,
            security_level: 128,
            pow_bits: default_max_pow(num_variables, 1),
            folding_factor: FoldingFactor::Constant(4),
            leaf_hash_params: (),
            two_to_one_params: (),
            soundness_type: SoundnessType::ConjectureList,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            batch_size,
        };
        WhirConfig::new(mv_params, whir_params)
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
        let io: IOPattern = self.create_io_pattern();

        let mut merlin = io.to_prover_state();
        let z = pad_to_power_of_two(witness.clone());
        let witness_polynomial_evals = EvaluationsList::new(z.clone());

        let (commitment_to_witness, masked_polynomial, random_polynomial) =
            batch_commmit_to_polynomial(
                self.m,
                &self.whir_witness,
                &witness_polynomial_evals,
                &mut merlin,
            );

        // First round of sumcheck to reduce R1CS to a batch weighted evaluation of the
        // witness
        let (mut merlin, alpha) = run_zk_sumcheck_prover(
            r1cs,
            &witness,
            merlin,
            self.m_0,
            &self.whir_for_hiding_spartan,
        );

        // Compute weights from R1CS instance
        let alphas = calculate_external_row_of_r1cs_matrices(&alpha, r1cs);

        let (statement, f_sums, g_sums) = create_combined_statement_over_two_polynomials::<3>(
            self.m,
            &commitment_to_witness,
            &masked_polynomial,
            &random_polynomial,
            &alphas,
        );

        let _ = merlin
            .hint::<(Vec<FieldElement>, Vec<FieldElement>)>(&(f_sums.to_vec(), g_sums.to_vec()));

        // Compute WHIR weighted batch opening proof
        let (mut merlin, col_randomness, deferred) =
            run_zk_whir_pcs_prover(commitment_to_witness, statement, &self.whir_witness, merlin);

        prove_spark(
            r1cs.a(),
            &mut merlin,
            &self.whir_config_a_num_terms,
            &self.whir_config_row,
            &self.whir_config_col,
            &alpha,
            &col_randomness.0,
            deferred[0],
        )?;

        let transcript = merlin.narg_string().to_vec();

        Ok(WhirR1CSProof { transcript })
    }

    #[instrument(skip_all)]
    #[allow(unused)] // TODO: Fix implementation
    pub fn verify(&self, proof: &WhirR1CSProof) -> Result<()> {
        // Set up transcript
        let io = self.create_io_pattern();
        let mut arthur = io.to_verifier_state(&proof.transcript);

        let commitment_reader = CommitmentReader::new(&self.whir_witness);
        let parsed_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

        let data_from_sumcheck_verifier = run_sumcheck_verifier(
            &mut arthur,
            self.m_0,
            &self.whir_for_hiding_spartan,
            // proof.whir_spartan_blinding_values,
        )
        .context("while verifying sumcheck")?;

        let whir_query_answer_sum_vectors: (Vec<FieldElement>, Vec<FieldElement>) =
            arthur.hint().unwrap();

        let whir_query_answer_sums = (
            whir_query_answer_sum_vectors.0.try_into().unwrap(),
            whir_query_answer_sum_vectors.1.try_into().unwrap(),
        );

        let statement_verifier = prepare_statement_for_witness_verifier::<3>(
            self.m,
            &parsed_commitment,
            &whir_query_answer_sums,
        );

        let (folding_randomness, deferred) = run_whir_pcs_verifier(
            &mut arthur,
            &parsed_commitment,
            &self.whir_witness,
            &statement_verifier,
        )
        .context("while verifying WHIR proof")?;

        // Check the Spartan sumcheck relation.
        ensure!(
            data_from_sumcheck_verifier.last_sumcheck_val
                == (whir_query_answer_sums.0[0] * whir_query_answer_sums.0[1]
                    - whir_query_answer_sums.0[2])
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        verify_spark(
            &mut arthur,
            &self.whir_config_a_num_terms,
            &self.whir_config_row,
            &self.whir_config_col,
            deferred[0],
            self.a_num_terms,
        );

        Ok(())
    }

    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> IOPattern {
        let mut io = IOPattern::new("🌪️")
            .commit_statement(&self.whir_witness)
            .add_rand(self.m_0)
            .commit_statement(&self.whir_for_hiding_spartan)
            .add_zk_sumcheck_polynomials(self.m_0)
            .add_whir_proof(&self.whir_for_hiding_spartan)
            .hint("claimed_evaluations")
            .add_whir_proof(&self.whir_witness);

        io = io.spark(
            &self.whir_config_a_num_terms,
            &self.whir_config_row,
            &self.whir_config_col,
            self.a_num_terms,
        );
        io
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
        prefix_sum += eval_cubic_poly(&g_univariates[i], &alphas[i]);
    }

    // s = Σ_{i>r}(g_i(0) + g_i(1))
    let mut suffix_sum = FieldElement::zero();
    for g_coeffs in g_univariates.iter().skip(compute_for + 1) {
        suffix_sum += eval_cubic_poly(g_coeffs, &FieldElement::zero())
            + eval_cubic_poly(g_coeffs, &FieldElement::one());
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
        let value = eval_cubic_poly(
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
    let fixed_variables: &[FieldElement] = &[];
    let polynomial_coefficient =
        compute_blinding_coefficients_for_round(g_univariates, 0, fixed_variables);

    eval_cubic_poly(&polynomial_coefficient, &FieldElement::zero())
        + eval_cubic_poly(&polynomial_coefficient, &FieldElement::one())
}

fn prepare_statement_for_witness_verifier<const N: usize>(
    m: usize,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    whir_query_answer_sums: &([FieldElement; N], [FieldElement; N]),
) -> Statement<FieldElement> {
    let mut statement_verifier = Statement::<FieldElement>::new(m);
    for i in 0..whir_query_answer_sums.0.len() {
        let claimed_sum = whir_query_answer_sums.0[i]
            + whir_query_answer_sums.1[i] * parsed_commitment.batching_randomness;
        statement_verifier.add_constraint(
            Weights::linear(EvaluationsList::new(vec![FieldElement::zero(); 1 << m])),
            claimed_sum,
        );
    }
    statement_verifier
}

pub fn batch_commmit_to_polynomial(
    m: usize,
    whir_config: &WhirConfig,
    witness: &EvaluationsList<FieldElement>,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
) -> (
    Witness<FieldElement, SkyscraperMerkleConfig>,
    EvaluationsList<FieldElement>,
    EvaluationsList<FieldElement>,
) {
    let mask = generate_mask(witness.evals().len());
    let masked_polynomial = create_masked_polynomial(witness, &mask);

    let masked_polynomial_coeff = masked_polynomial.to_coeffs();

    let random_polynomial_eval = generate_random_multilinear_polynomial(m);
    let random_polynomial_coeff = random_polynomial_eval.to_coeffs();

    let committer = CommitmentWriter::new(whir_config.clone());
    let witness_new = committer
        .commit_batch(merlin, &[
            masked_polynomial_coeff.clone(),
            random_polynomial_coeff.clone(),
        ])
        .expect("WHIR prover failed to commit");

    (witness_new, masked_polynomial, random_polynomial_eval)
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

#[instrument(skip_all)]
pub fn run_zk_sumcheck_prover(
    r1cs: &R1CS,
    z: &[FieldElement],
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m_0: usize,
    whir_for_blinding_of_spartan_config: &WhirConfig,
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

    let blinding_polynomial = generate_blinding_spartan_univariate_polys(m_0);

    let blinding_polynomial_for_commiting = EvaluationsList::new(pad_to_power_of_two(
        blinding_polynomial.iter().flatten().cloned().collect(),
    ));
    let blinding_polynomial_variables = blinding_polynomial_for_commiting.num_variables();
    let (commitment_to_blinding_polynomial, blindings_mask_polynomial, blindings_blind_polynomial) =
        batch_commmit_to_polynomial(
            blinding_polynomial_variables + 1,
            whir_for_blinding_of_spartan_config,
            &blinding_polynomial_for_commiting,
            &mut merlin,
        );

    let sum_g_reduce = sum_over_hypercube(blinding_polynomial.as_slice());

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
            eval_cubic_poly(&combined_hhat_i_coeffs, &alpha_i);
    }

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

    let (merlin, _sums, _deferred) = run_zk_whir_pcs_prover(
        commitment_to_blinding_polynomial,
        statement,
        whir_for_blinding_of_spartan_config,
        merlin,
    );

    (merlin, alpha)
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
    num_vars: usize,
    witness: &Witness<FieldElement, SkyscraperMerkleConfig>,
    f_polynomial: &EvaluationsList<FieldElement>,
    g_polynomial: &EvaluationsList<FieldElement>,
    alphas: &[Vec<FieldElement>],
) -> (
    Statement<FieldElement>,
    [FieldElement; N],
    [FieldElement; N],
) {
    let mut statement = Statement::<FieldElement>::new(num_vars);
    let mut f_sums = [FieldElement::zero(); N];
    let mut g_sums = [FieldElement::zero(); N];

    for (idx, alpha) in alphas.iter().enumerate() {
        let mut expanded_alphas = pad_to_power_of_two(alpha.clone());
        expanded_alphas.resize(expanded_alphas.len() * 2, FieldElement::zero());

        let weight = Weights::linear(EvaluationsList::new(expanded_alphas));
        let f = weight.weighted_sum(f_polynomial);
        let g = weight.weighted_sum(g_polynomial);

        statement.add_constraint(weight, f + witness.batching_randomness * g);

        f_sums[idx] = f;
        g_sums[idx] = g;
    }

    (statement, f_sums, g_sums)
}

#[instrument(skip_all)]
pub fn run_zk_whir_pcs_prover(
    witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    statement: Statement<FieldElement>,
    params: &WhirConfig,
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
) -> (
    ProverState<SkyscraperSponge, FieldElement>,
    MultilinearPoint<FieldElement>,
    Vec<FieldElement>,
) {
    info!("WHIR Parameters: {params}");

    if !params.check_pow_bits() {
        warn!("More PoW bits required than specified.");
    }

    let prover = Prover(params.clone());
    let (randomness, deferred) = prover
        .prove(&mut merlin, statement, witness)
        .expect("WHIR prover failed to generate a proof");

    (merlin, randomness, deferred)
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
    whir_for_spartan_blinding_config: &WhirConfig,
) -> Result<DataFromSumcheckVerifier> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let commitment_reader = CommitmentReader::new(whir_for_spartan_blinding_config);
    let parsed_commitment = commitment_reader.parse_commitment(arthur).unwrap();

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
        let hhat_i_at_zero = eval_cubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(&hhat_i, &alpha_i[0]);
    }
    let mut values_of_polynomial_sums = [FieldElement::zero(); 2];
    let _ = arthur.fill_next_scalars(&mut values_of_polynomial_sums);

    let statement_verifier = prepare_statement_for_witness_verifier::<1>(
        whir_for_spartan_blinding_config.mv_parameters.num_variables,
        &parsed_commitment,
        &([values_of_polynomial_sums[0]], [
            values_of_polynomial_sums[1]
        ]),
    );
    run_whir_pcs_verifier(
        arthur,
        &parsed_commitment,
        whir_for_spartan_blinding_config,
        &statement_verifier,
    )
    .context("while verifying WHIR")?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * values_of_polynomial_sums[0];

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
) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
    let verifier = Verifier::new(params);

    let (folding_randomness, deferred) = verifier
        .verify(arthur, parsed_commitment, statement_verifier)
        .context("while verifying WHIR")?;

    Ok((folding_randomness, deferred))
}
